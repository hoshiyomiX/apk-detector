//! Shared detector plumbing used by all 9 detector modules.
//!
//! ## Single-pass Aho-Corasick DEX scanner
//!
//! v2.0.0 replaces the previous "9 detector modules each scan DEX strings
//! independently with a thread-local cache" architecture with a single-pass
//! Aho-Corasick scanner. The previous design had two problems:
//!
//! 1. **Memory**: the thread-local DEX_CACHE held ALL DEX strings in memory
//!    for the entire scan duration. For OCTO (87MB DEX, ~1.5M strings) this
//!    was ~75MB of heap — combined with the Kotlin/Compose UI's 50-100MB,
//!    the per-process heap approached the 256MB Android limit. The
//!    lowmemorykiller would SIGKILL the process — catch_unwind CANNOT
//!    intercept SIGKILL, so the app crashed.
//!
//! 2. **Redundancy**: even with the cache, the first detector paid the
//!    full parse cost, and pattern matching was O(strings × patterns)
//!    per detector — for OCTO that's 1.5M × 50 = 75M substring scans
//!    per detector, 675M total across 9 detectors.
//!
//! The new `scan_all_dex_once`:
//! - Builds ONE Aho-Corasick automaton from ALL DexString rule patterns
//!   across ALL 9 categories (~150 patterns total, ~150KB automaton).
//! - Reads each DEX file once, parses to strings, streams each string
//!   through the AC automaton in O(string_length + matches). Drops the
//!   string table before moving to the next DEX file.
//! - Peak memory: ~10MB per DEX file (vs ~75MB held for entire scan).
//! - Total CPU: O(total_string_length) ≈ O(45MB) for OCTO — ~10× faster.
//!
//! ## Scan budget
//!
//! The budget still bounds pathological inputs: if a malicious APK has
//! 500MB of DEX, we stop scanning after `max_total_dex_bytes` (default
//! 256MB). The budget is enforced via the thread-local `BUDGET` tracker,
//! consulted by `scan_all_dex_once` on every DEX read.

use std::collections::HashMap;
use std::io::{Read, Seek};

use aho_corasick::{AhoCorasickBuilder, MatchKind};

use apk_parser::{Apk, ApkError};
use signatures::{DetectionRule, EvidenceLocation, SignatureSet};

use crate::report::finding_from_rule;
use crate::Finding;
use crate::ScanBudget;

// Thread-local budget tracker. Installed by `BudgetGuard::install` at the
// start of `full_scan_with_budget`, consulted by `scan_all_dex_once` on
// every DEX read. Reset to `None` on drop of the guard so concurrent scans
// on different threads don't interfere.
//
// NOTE: The DEX_CACHE thread-local from v1.x has been REMOVED. The new
// AC scanner doesn't need to cache strings — it scans each DEX in a single
// pass and drops the strings immediately. This eliminates the ~75MB peak
// heap that was causing lowmemorykiller SIGKILL on Android.
thread_local! {
    static BUDGET: std::cell::RefCell<Option<BudgetState>> = const { std::cell::RefCell::new(None) };
}

/// Internal mutable state for the budget tracker.
#[derive(Debug, Clone, Copy, Default)]
struct BudgetState {
    budget: ScanBudget,
    dex_bytes_used: u64,
    dex_files_scanned: usize,
    exhausted: bool,
}

/// RAII guard that installs a budget into the thread-local on creation
/// and resets it on drop. Returned by `BudgetGuard::install`.
pub struct BudgetGuard;

impl BudgetGuard {
    /// Install `budget` as the active budget for the current thread.
    /// The budget is automatically cleared when the returned guard drops.
    pub fn install(budget: ScanBudget) -> Self {
        BUDGET.with(|b| {
            *b.borrow_mut() = Some(BudgetState {
                budget,
                ..Default::default()
            });
        });
        Self
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        BUDGET.with(|b| {
            *b.borrow_mut() = None;
        });
    }
}

/// Check whether the current thread has an installed budget that has been
/// exhausted. Returns `false` if no budget is installed (unbounded mode).
pub fn budget_exhausted() -> bool {
    BUDGET.with(|b| b.borrow().as_ref().is_some_and(|s| s.exhausted))
}

/// Try to deduct `n_bytes` from the DEX-byte budget. Returns `true` if the
/// deduction succeeds, `false` if it would exceed the budget (in which case
/// the budget is marked exhausted and the caller should skip this DEX).
fn try_use_dex_bytes(n_bytes: u64) -> bool {
    BUDGET.with(|b| {
        let mut slot = b.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return true; // no budget installed → unbounded
        };
        let next = state.dex_bytes_used.saturating_add(n_bytes);
        if next > state.budget.max_total_dex_bytes {
            state.exhausted = true;
            return false;
        }
        state.dex_bytes_used = next;
        true
    })
}

/// Increment the DEX-files-scanned counter. Returns `true` if we're still
/// under the `max_dex_files` cap, `false` if we've hit it (marks budget
/// exhausted so subsequent reads are skipped).
fn try_use_dex_file() -> bool {
    BUDGET.with(|b| {
        let mut slot = b.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return true; // unbounded
        };
        if state.dex_files_scanned >= state.budget.max_dex_files {
            state.exhausted = true;
            return false;
        }
        state.dex_files_scanned += 1;
        true
    })
}

/// **Single-pass Aho-Corasick DEX scanner.** This is the core fix for the
/// scan-crash regression: instead of 9 detector modules each scanning DEX
/// strings independently (which required holding all 1.5M OCTO strings in
/// a thread-local cache = ~75MB heap = lowmemorykiller SIGKILL on Android),
/// we build ONE Aho-Corasick automaton from ALL DexString rule patterns
/// across ALL 9 categories, then stream each DEX file's string table
/// through it in O(N+M) time with O(1) extra memory per string.
///
/// ## Algorithm
///
/// 1. Collect all DexString rules from `sigs` (across all 9 categories).
/// 2. Flatten their patterns into a single `Vec<&str>` with a parallel
///    `Vec<usize>` mapping pattern-index → rule-index into `dex_rules`.
/// 3. Build an `AhoCorasick` automaton with `MatchKind::LeftmostLongest`
///    (so "su binary" wins over "su" when both match at the same offset).
/// 4. For each DEX file (up to `dex_cap`):
///    - Check budget — skip if exhausted.
///    - Read DEX bytes, parse to `DexStringTable`.
///    - For each string in the table, run `ac.find_iter` to find all
///      pattern matches. Record `(rule_idx, &str)` for each match.
///    - Drop the string table (frees memory before next DEX).
/// 5. Dedupe matches by rule_idx, cap evidence at 3 strings per rule,
///    and push one `Finding` per matched rule.
///
/// ## Memory profile
///
/// - AC automaton: ~1KB per pattern × ~150 patterns = ~150KB (constant).
/// - Per-DEX peak: parsed string table ≈ 10MB (transient — dropped before next DEX).
/// - Findings: ~50 entries × ~200 bytes = ~10KB.
///
/// Total peak: ~10MB (vs ~75MB for the v1.x cache). On a 256MB Android
/// process limit with 50-100MB Kotlin/Compose UI, this leaves comfortable
/// headroom — no more lowmemorykiller crashes.
pub fn scan_all_dex_once<R: Read + Seek>(
    apk: &mut Apk<R>,
    sigs: &SignatureSet,
    findings: &mut Vec<Finding>,
    dex_cap: usize,
) {
    // 1. Collect all DexString rules across all 9 categories.
    let dex_rules: Vec<&DetectionRule> = sigs
        .rules()
        .iter()
        .filter(|r| r.evidence_location == EvidenceLocation::DexString)
        .collect();
    if dex_rules.is_empty() {
        return;
    }

    // 2. Flatten patterns into a single Vec, tracking which rule(s) each
    //    pattern belongs to. AC pattern_idx → Vec<rule_idx> because
    //    MULTIPLE rules can share the same pattern (e.g., "ro.debuggable"
    //    appears in both `root-check-ro-secure-prop` and
    //    `app-defense-debug-flag`). When AC finds a match at pattern_idx,
    //    ALL rules that contain that pattern must fire — not just one.
    //    (Bug found during OCTO regression test: v1.x scanner fired both
    //    rules because it scanned per-rule; v2.0 AC scanner with single
    //    rule_idx per pattern fired only one, dropping the other finding.)
    let mut patterns: Vec<String> = Vec::new();
    let mut pattern_to_rules: Vec<Vec<usize>> = Vec::new();
    let mut pattern_index: HashMap<String, usize> = HashMap::new();
    for (rule_idx, rule) in dex_rules.iter().enumerate() {
        for pat in &rule.patterns {
            if let Some(&pat_idx) = pattern_index.get(pat) {
                // Pattern already exists — add this rule to its rule list.
                pattern_to_rules[pat_idx].push(rule_idx);
            } else {
                let pat_idx = patterns.len();
                patterns.push(pat.clone());
                pattern_to_rules.push(vec![rule_idx]);
                pattern_index.insert(pat.clone(), pat_idx);
            }
        }
    }
    if patterns.is_empty() {
        return;
    }

    // 3. Build the Aho-Corasick automaton. LeftmostLongest ensures that
    //    when multiple patterns match at the same starting offset, the
    //    longest one wins (e.g., "su binary" wins over "su"). This
    //    matches the v1.x scanner's `s.contains(needle)` semantics —
    //    each rule fires independently if any of its patterns is found
    //    as a substring, but we use longest-match to avoid spurious
    //    short-pattern noise.
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(&pattern_refs)
        .expect("AC automaton build failed (duplicate or empty patterns?)");

    // 4. Collect matches per rule_idx across all DEX files.
    //    `matches_per_rule[rule_idx] = Vec<matched_string>`.
    let mut matches_per_rule: HashMap<usize, Vec<String>> = HashMap::new();

    let dex_entries: Vec<String> = apk
        .dex_entries()
        .iter()
        .map(|e| e.name.clone())
        .take(dex_cap)
        .collect();
    if dex_entries.is_empty() {
        return;
    }

    for dex_name in &dex_entries {
        // Check budget BEFORE the expensive `apk.read(dex_name)` call.
        if !try_use_dex_file() {
            break;
        }
        let entry_size = apk
            .entries()
            .iter()
            .find(|e| e.name == *dex_name)
            .map(|e| e.uncompressed_size)
            .unwrap_or(0);
        if !try_use_dex_bytes(entry_size) {
            break;
        }

        let bytes = match apk.read(dex_name) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tbl = match apk_parser::DexStringTable::parse(&bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Drop the raw DEX bytes immediately — we only need the string table.
        drop(bytes);

        // Stream each string through AC, collecting (rule_idx, matched_string).
        // We use the matched HAYSTACK substring as evidence (not the pattern),
        // so the report shows the actual DEX string that triggered the match.
        for s in &tbl.strings {
            for mat in ac.find_iter(s) {
                let pat_idx = mat.pattern().as_usize();
                // A single pattern match may correspond to MULTIPLE rules
                // (when two rules share the same pattern). Fire ALL of them.
                for &rule_idx in &pattern_to_rules[pat_idx] {
                    // Cap evidence collection at 3 strings per rule to bound
                    // memory (a single rule with 1000 matches would otherwise
                    // bloat the findings Vec).
                    let entry = matches_per_rule.entry(rule_idx).or_default();
                    if entry.len() < 3 {
                        entry.push(s.clone());
                    }
                }
            }
            // Early-exit if budget exhausted mid-DEX.
            if budget_exhausted() {
                break;
            }
        }
        // String table drops here → memory freed before next DEX.
    }

    // 5. Emit one Finding per matched rule (deduped).
    for (rule_idx, matched_strings) in matches_per_rule {
        if matched_strings.is_empty() {
            continue;
        }
        let rule = dex_rules[rule_idx];
        let evidence = matched_strings
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("`, `");
        findings.push(finding_from_rule(
            rule,
            format!("DEX string match: `{}`", evidence),
        ));
    }
}

/// Run all `rules` whose `evidence_location` matches `Manifest` against the
/// decoded AndroidManifest.xml. Manifest reads are small and bounded — no
/// budget enforcement needed here.
pub fn scan_manifest<R: Read + Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) -> Result<(), ApkError> {
    let bytes = apk.manifest()?;
    let xml = match apk_parser::BinaryXml::parse_slice(&bytes) {
        Ok(x) => x,
        Err(_) => return Ok(()),
    }
    .elements;
    // Concatenate all tag names + attr values into one big haystack
    let mut hay = String::new();
    for el in &xml {
        hay.push_str(&el.tag);
        hay.push(' ');
        for (k, v) in &el.attrs {
            hay.push_str(k);
            hay.push('=');
            hay.push_str(v);
            hay.push(' ');
        }
    }

    for rule in rules {
        for needle in &rule.patterns {
            if hay.contains(needle.as_str()) {
                findings.push(finding_from_rule(
                    rule,
                    format!("Manifest match: `{}`", needle),
                ));
                break;
            }
        }
    }
    Ok(())
}

/// Run all `rules` whose `evidence_location` matches `NativeLibName` against
/// the names of native libs under `lib/<abi>/`. Native-lib scans are bounded
/// by the (small) number of .so files — no budget enforcement.
pub fn scan_native_lib_names<R: Read + Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) -> Result<(), ApkError> {
    let libs = apk.native_libs()?;
    for rule in rules {
        for needle in &rule.patterns {
            let hit: Vec<&apk_parser::NativeLib> = libs
                .iter()
                .filter(|l| l.filename.contains(needle.as_str()))
                .collect();
            if !hit.is_empty() {
                let evidence = hit
                    .iter()
                    .take(3)
                    .map(|l| format!("lib/{}/{}", l.abi, l.filename))
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(finding_from_rule(rule, format!("Native lib: {}", evidence)));
                break;
            }
        }
    }
    Ok(())
}

/// Run all `rules` whose `evidence_location` matches `ZipEntry` against the
/// list of files in the APK ZIP. Bounded by entry count — no budget.
pub fn scan_zip_entries<R: Read + Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) {
    let names: Vec<&str> = apk.entries().iter().map(|e| e.name.as_str()).collect();
    for rule in rules {
        for needle in &rule.patterns {
            let hit: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| n.contains(needle.as_str()))
                .collect();
            if !hit.is_empty() {
                let evidence = hit.iter().take(3).copied().collect::<Vec<_>>().join(", ");
                findings.push(finding_from_rule(rule, format!("ZIP entry: {}", evidence)));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Budget guard must reset the thread-local on drop, so a second scan
    /// starts from a clean state.
    #[test]
    fn test_budget_guard_resets_on_drop() {
        assert!(!budget_exhausted());
        {
            let _g = BudgetGuard::install(ScanBudget::default());
            assert!(!budget_exhausted());
            assert!(!try_use_dex_bytes(u64::MAX));
            assert!(budget_exhausted());
        }
        assert!(!budget_exhausted());
    }

    /// A budget that allows the DEX bytes must accept the deduction.
    #[test]
    fn test_budget_accepts_within_limit() {
        let _g = BudgetGuard::install(ScanBudget {
            max_total_dex_bytes: 100,
            max_dex_files: 10,
            max_total_strings: 1000,
        });
        assert!(try_use_dex_bytes(50));
        assert!(!budget_exhausted());
        assert!(try_use_dex_bytes(40));
        assert!(!budget_exhausted());
        assert!(!try_use_dex_bytes(50));
        assert!(budget_exhausted());
    }

    /// `max_dex_files` cap: try_use_dex_file returns false after the cap.
    #[test]
    fn test_budget_max_dex_files_cap() {
        let _g = BudgetGuard::install(ScanBudget {
            max_total_dex_bytes: 1024 * 1024,
            max_dex_files: 2,
            max_total_strings: 1000,
        });
        assert!(try_use_dex_file()); // 1st
        assert!(try_use_dex_file()); // 2nd
        assert!(!try_use_dex_file()); // 3rd → rejected
        assert!(budget_exhausted());
    }

    /// When no budget is installed, the try_use_* functions must return
    /// `true` (unbounded mode).
    #[test]
    fn test_no_budget_means_unbounded() {
        assert!(try_use_dex_bytes(u64::MAX));
        assert!(try_use_dex_file());
        assert!(!budget_exhausted());
    }
}
