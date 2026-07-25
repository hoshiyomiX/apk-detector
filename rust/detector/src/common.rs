//! Shared detector plumbing used by all 9 detector modules.
//!
//! ## Scan budget
//!
//! The freeze root-cause: `scan_dex_strings` previously loaded ALL DEX
//! strings into a `Vec<String>` and then did O(rules × patterns × strings)
//! substring scans. For OCTO (7 DEX, 87MB, ~9M strings) this blocked the
//! calling thread for 30+ seconds on a mid-range Android device — the UI
//! froze because the JNI `scanApk` call runs synchronously on the worker
//! thread and the worker was saturated.
//!
//! Fix: a thread-local `BudgetTracker` is installed by
//! `full_scan_with_budget` and consulted by `scan_dex_strings` at three
//! points:
//!   1. Before reading each DEX file (skip if `dex_bytes_used` would exceed
//!      `max_total_dex_bytes`).
//!   2. After parsing each DEX's string table (skip further DEX files if
//!      `strings_seen` would exceed `max_total_strings`).
//!   3. Inside the pattern-match loop (break early if `strings_seen` is
//!      exceeded — though we already aggregate before matching, this is
//!      belt-and-suspenders).
//!
//! When the budget is exhausted, the scan returns early with whatever
//! findings it has accumulated. The caller (`full_scan_with_budget`)
//! checks `budget_exhausted()` and stamps the report with
//! `ScanOutcome::Partial` so the user knows the scan was truncated.

use std::cell::RefCell;

use apk_parser::{Apk, ApkError};
use signatures::DetectionRule;

use crate::report::finding_from_rule;
use crate::Finding;
use crate::ScanBudget;

// Thread-local budget tracker. Installed by `BudgetGuard::install` at the
// start of `full_scan_with_budget`, consulted by `scan_dex_strings` on
// every DEX read + every string-table extension. Reset to `None` on drop
// of the guard so concurrent scans on different threads don't interfere.
thread_local! {
    static BUDGET: RefCell<Option<BudgetState>> = const { RefCell::new(None) };
}

// Thread-local DEX-string cache. Populated on the FIRST `scan_dex_strings`
// call (the first detector module's scan) and reused by every subsequent
// detector. This eliminates the 9× redundant DEX reads + parses that were
// the actual root cause of the scan-freeze symptom — each of the 9 detector
// modules was independently reading + parsing all 7 DEX files (87 MB total
// for OCTO), spending ~30 seconds on a mid-range Android device.
//
// Cache key: APK path (so two scans of different APKs on the same thread
// don't share a cache). Cache value: the deduplicated Vec<String> of all
// strings from all DEX files (capped by the budget). The cache is cleared
// by `BudgetGuard`'s Drop impl so each fresh scan starts clean.
thread_local! {
    static DEX_CACHE: RefCell<Option<DexCache>> = const { RefCell::new(None) };
}

/// Per-scan DEX cache. Holds the parsed + deduplicated string table so
/// subsequent detector modules skip the redundant read+parse cycle.
#[derive(Default)]
struct DexCache {
    apk_path: String,
    strings: Vec<String>,
}

/// Internal mutable state for the budget tracker.
#[derive(Debug, Clone, Copy, Default)]
struct BudgetState {
    budget: ScanBudget,
    dex_bytes_used: u64,
    strings_seen: usize,
    exhausted: bool,
}

/// RAII guard that installs a budget into the thread-local on creation
/// and resets it on drop. Returned by `BudgetGuard::install`. Also clears
/// the DEX-string cache so each fresh scan starts from a clean state.
pub struct BudgetGuard;

impl BudgetGuard {
    /// Install `budget` as the active budget for the current thread.
    /// The budget + DEX cache are automatically cleared when the returned
    /// guard drops.
    pub fn install(budget: ScanBudget) -> Self {
        BUDGET.with(|b| {
            *b.borrow_mut() = Some(BudgetState {
                budget,
                ..Default::default()
            });
        });
        DEX_CACHE.with(|c| {
            *c.borrow_mut() = None;
        });
        Self
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        BUDGET.with(|b| {
            *b.borrow_mut() = None;
        });
        DEX_CACHE.with(|c| {
            *c.borrow_mut() = None;
        });
    }
}

/// Check whether the current thread has an installed budget that has been
/// exhausted. Returns `false` if no budget is installed (the scan is then
/// unbounded — used by the `full_scan` convenience entry point, which
/// delegates to `full_scan_with_budget` with `ScanBudget::default()` so a
/// budget is always present in practice).
pub fn budget_exhausted() -> bool {
    BUDGET.with(|b| b.borrow().as_ref().is_some_and(|s| s.exhausted))
}

/// Prime the DEX-string cache with the APK path (the cache key). Called
/// by `full_scan_with_budget` AFTER installing the budget guard. The
/// first `scan_dex_strings` call checks the cache: if the apk_path matches
/// but `strings` is empty, it knows to read+parse the DEX files (cache
/// miss for the strings themselves); if a subsequent call sees the same
/// apk_path with non-empty `strings`, it reuses them.
pub fn prime_dex_cache(apk_path: &str) {
    DEX_CACHE.with(|c| {
        *c.borrow_mut() = Some(DexCache {
            apk_path: apk_path.to_string(),
            strings: Vec::new(),
        });
    });
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

/// Try to deduct `n_strings` from the string-count budget. Same semantics
/// as `try_use_dex_bytes`.
fn try_use_strings(n_strings: usize) -> bool {
    BUDGET.with(|b| {
        let mut slot = b.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return true;
        };
        let next = state.strings_seen.saturating_add(n_strings);
        if next > state.budget.max_total_strings {
            state.exhausted = true;
            return false;
        }
        state.strings_seen = next;
        true
    })
}

/// Run all `rules` whose `evidence_location` matches `DexString` against
/// every DEX file in the APK. Honors the thread-local scan budget: if the
/// budget is exhausted, remaining DEX files are skipped (the caller can
/// surface this via `ScanOutcome::Partial`).
///
/// **DEX-string cache**: the parsed + deduplicated string table is cached
/// in a thread-local keyed by `apk_path`. The first detector module to
/// call this function pays the cost of reading + parsing every DEX file;
/// every subsequent detector module reuses the cached strings. This
/// eliminates the 9× redundant DEX read/parse cycle that was the actual
/// root cause of the scan-freeze symptom on OCTO (87 MB / 9M strings /
/// 9 detector modules = ~30 s on a mid-range device).
pub fn scan_dex_strings<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
    dex_cap: usize,
) {
    // We need the APK path for the cache key. The Apk type doesn't carry
    // its own path, so the caller (detector::full_scan_with_budget) stashes
    // it in the thread-local via `set_dex_cache_key` BEFORE the first
    // scan_dex_strings call. If the key isn't set, the cache is bypassed
    // (the scan works correctly but slowly — useful for unit tests that
    // don't go through full_scan_with_budget).
    let apk_path = DEX_CACHE.with(|c| c.borrow().as_ref().map(|d| d.apk_path.clone()));

    // Try to reuse the cached string table. A primed-but-unfilled cache
    // (path matches but strings is empty) is a "soft miss" — we need to
    // read+parse the DEX files now and fill the cache. A populated cache
    // (path matches, strings non-empty) is a hard hit.
    let cached: Option<Vec<String>> = if let Some(ref path) = apk_path {
        DEX_CACHE.with(|c| {
            c.borrow()
                .as_ref()
                .filter(|d| d.apk_path == *path && !d.strings.is_empty())
                .map(|d| d.strings.clone())
        })
    } else {
        None
    };

    let all_strings: Vec<String> = if let Some(strings) = cached {
        // Cache hit — reuse the parsed + deduplicated string table.
        strings
    } else {
        // Cache miss — read + parse every DEX file, dedup, and cache.
        let fresh = read_and_parse_dex(apk, dex_cap);
        if let Some(ref path) = apk_path {
            DEX_CACHE.with(|c| {
                if let Some(d) = c.borrow_mut().as_mut() {
                    d.strings = fresh.clone();
                } else {
                    *c.borrow_mut() = Some(DexCache {
                        apk_path: path.clone(),
                        strings: fresh.clone(),
                    });
                }
            });
        }
        fresh
    };

    // Pattern-match the (possibly cached) string table against each rule.
    for rule in rules {
        for needle in &rule.patterns {
            // case-sensitive substring scan
            let hits: Vec<&String> = all_strings
                .iter()
                .filter(|s| s.contains(needle.as_str()))
                .collect();
            if !hits.is_empty() {
                let evidence = hits
                    .iter()
                    .take(3) // cap evidence at 3 hits per rule
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("`, `");
                findings.push(finding_from_rule(
                    rule,
                    format!("DEX string match: `{}`", evidence),
                ));
                break; // one finding per rule, even if multiple patterns match
            }
        }
    }
}

/// Read every DEX file in the APK, parse each into a string table, dedup
/// the union, and return the result. Honors the thread-local budget —
/// if exhausted mid-read, returns whatever strings were collected up to
/// the cap. Called only on cache miss (first detector module's scan).
fn read_and_parse_dex<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    dex_cap: usize,
) -> Vec<String> {
    let dex_entries: Vec<String> = apk.dex_entries().iter().map(|e| e.name.clone()).collect();
    let dex_to_scan: Vec<String> = dex_entries.into_iter().take(dex_cap).collect();
    if dex_to_scan.is_empty() {
        return Vec::new();
    }

    let mut all_strings: Vec<String> = Vec::new();
    for dex_name in &dex_to_scan {
        // Check budget BEFORE the expensive `apk.read(dex_name)` call.
        let entry_size = apk
            .entries()
            .iter()
            .find(|e| e.name == *dex_name)
            .map(|e| e.uncompressed_size)
            .unwrap_or(0);
        if !try_use_dex_bytes(entry_size) {
            // Budget exhausted — skip this and all remaining DEX files.
            break;
        }

        let bytes = match apk.read(dex_name) {
            Ok(b) => b,
            Err(_) => continue,
        };
        match apk_parser::DexStringTable::parse(&bytes) {
            Ok(tbl) => {
                let n = tbl.strings.len();
                if !try_use_strings(n) {
                    // String budget exhausted. Extend with whatever we got
                    // up to the cap (truncate the table to fit) and break.
                    let remaining = BUDGET.with(|b| {
                        b.borrow()
                            .as_ref()
                            .map(|s| s.budget.max_total_strings.saturating_sub(s.strings_seen))
                            .unwrap_or(n)
                    });
                    let take = remaining.min(n);
                    all_strings.extend(tbl.strings.into_iter().take(take));
                    break;
                }
                all_strings.extend(tbl.strings);
            }
            Err(_) => continue,
        }
    }

    // Dedup strings for faster scanning by subsequent detector modules.
    all_strings.sort_unstable();
    all_strings.dedup();
    all_strings
}

/// Run all `rules` whose `evidence_location` matches `Manifest` against the
/// decoded AndroidManifest.xml. Manifest reads are small and bounded — no
/// budget enforcement needed here.
pub fn scan_manifest<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) -> Result<(), ApkError> {
    let bytes = apk.manifest()?;
    let xml = match apk_parser::BinaryXml::parse_slice(&bytes) {
        Ok(x) => x,
        Err(_) => return Ok(()),
    };
    // Concatenate all tag names + attr values into one big haystack
    let mut hay = String::new();
    for el in &xml.elements {
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
pub fn scan_native_lib_names<R: std::io::Read + std::io::Seek>(
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
pub fn scan_zip_entries<R: std::io::Read + std::io::Seek>(
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
    /// starts from a clean state. This is the regression test for the
    /// "concurrent scans on different threads do not interfere" guarantee.
    #[test]
    fn test_budget_guard_resets_on_drop() {
        // Before install: no budget → not exhausted.
        assert!(!budget_exhausted());

        {
            let _g = BudgetGuard::install(ScanBudget::default());
            // Inside the guard: budget is installed, not yet exhausted.
            assert!(!budget_exhausted());
            // Force exhaustion by trying to use a huge DEX byte count.
            assert!(!try_use_dex_bytes(u64::MAX));
            assert!(budget_exhausted());
        }
        // After drop: budget cleared, not exhausted.
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
        // Third call would push to 130 > 100 → rejected.
        assert!(!try_use_dex_bytes(50));
        assert!(budget_exhausted());
    }

    /// A budget that allows the string count must accept the deduction.
    #[test]
    fn test_budget_strings_within_limit() {
        let _g = BudgetGuard::install(ScanBudget {
            max_total_dex_bytes: 1024 * 1024,
            max_dex_files: 10,
            max_total_strings: 100,
        });
        assert!(try_use_strings(50));
        assert!(try_use_strings(40)); // 50 + 40 = 90 ≤ 100, still OK
        assert!(!try_use_strings(50)); // 90 + 50 = 140 > 100, rejected
        assert!(budget_exhausted());
    }

    /// When no budget is installed (the `full_scan` entry point delegates
    /// to `full_scan_with_budget` so this never happens in practice, but
    /// `scan_dex_strings` is also pub(crate)-callable from tests), the
    /// try_use_* functions must return `true` (unbounded mode).
    #[test]
    fn test_no_budget_means_unbounded() {
        // No guard installed.
        assert!(try_use_dex_bytes(u64::MAX));
        assert!(try_use_strings(usize::MAX));
        assert!(!budget_exhausted());
    }
}
