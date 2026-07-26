//! # detector
//!
//! 9 detector modules + bypass hints + Markdown report + diff engine +
//! device-profile simulator.
//!
//! Each detector consumes an `Apk` and a `&SignatureSet`, and produces a
//! list of `Finding` values. The `Report` type aggregates findings across
//! all categories and renders Markdown for the UI. The `simulator` module
//! takes a `Report` + a `DeviceProfile` and predicts which findings would
//! actually trigger on the user's device.

pub mod anti_emulator;
pub mod anti_hooking;
pub mod anti_tamper;
pub mod app_defense;
pub mod app_hardening;
pub mod bypass_hints;
pub mod clone_repackage;
pub mod common;
pub mod diff;
pub mod mtd_rasp;
pub mod play_integrity;
pub mod report;
pub mod root;
pub mod simulator;

pub use diff::ReportDiff;
pub use report::{Finding, Report, ScanOutcome};
pub use simulator::{simulate, DeviceProfile, SimulationReport, SimulationVerdict};

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::SignatureSet;

/// Per-scan budget. Bounds scan time on huge multidex APKs (the OCTO
/// dissection revealed 7 DEX files totalling ~87MB, ~9M DEX strings —
/// scanning every string synchronously froze the JNI calling thread for
/// 30+ seconds on a mid-range device).
///
/// The budget is intentionally permissive (most apps fit comfortably under
/// 10MB of DEX) but caps pathological inputs to keep scan time bounded.
#[derive(Debug, Clone, Copy)]
pub struct ScanBudget {
    /// Maximum total bytes of DEX data to decompress + parse across all
    /// DEX files. Default 256 MB — covers OCTO (87 MB) with headroom.
    pub max_total_dex_bytes: u64,
    /// Maximum number of DEX files to scan. Default 10 — covers AndroidX
    /// multidex limits (10 is the AndroidX hard cap before LMR1).
    pub max_dex_files: usize,
    /// Maximum number of DEX strings to aggregate across all DEX files
    /// before pattern matching. Default 4 million — OCTO produces ~1.5M
    /// strings total, so this is 2.5x headroom.
    pub max_total_strings: usize,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            max_total_dex_bytes: 256 * 1024 * 1024,
            max_dex_files: 10,
            max_total_strings: 4_000_000,
        }
    }
}

/// Convenience: scan an APK against every category, return a fully-rendered
/// `Report`. Uses the default `ScanBudget`. The caller is responsible for
/// `apk_path` being a real file (used only for display in the report).
pub fn full_scan<R: Read + Seek>(apk_path: &str, apk: &mut Apk<R>, sigs: &SignatureSet) -> Report {
    full_scan_with_budget(apk_path, apk, sigs, ScanBudget::default())
}

/// Scan with an explicit budget. Use this from JNI / CLI when you need to
/// bound scan time on potentially-huge APKs. If the budget is exceeded the
/// scan returns a `Report` with `outcome = ScanOutcome::Partial(reason)`;
/// findings collected up to that point are still included.
///
/// Implementation: the budget is enforced via a thread-local `BudgetTracker`
/// (see `common::BUDGET`). This avoids refactoring every detector module's
/// `scan()` signature — the per-module scans call `common::scan_dex_strings`
/// which reads the thread-local and short-circuits when exhausted. The
/// thread-local is scoped to this function via a guard that resets it on
/// drop, so concurrent scans on different threads do not interfere.
pub fn full_scan_with_budget<R: Read + Seek>(
    apk_path: &str,
    apk: &mut Apk<R>,
    sigs: &SignatureSet,
    budget: ScanBudget,
) -> Report {
    let mut report = Report::new(apk_path);
    report.signature_count = sigs.len();

    // Manifest-derived metadata
    if let Ok(manifest_bytes) = apk.manifest() {
        if let Ok(xml) = apk_parser::BinaryXml::parse_slice(&manifest_bytes) {
            report.apk_package = xml.package().map(|s| s.to_string());
        }
    }
    // APK file size approximation: sum of all entry uncompressed sizes
    report.apk_size_bytes = apk.entries().iter().map(|e| e.uncompressed_size).sum();

    // Install the budget for the duration of this scan. The guard resets
    // the thread-local on drop so a subsequent scan with a different budget
    // starts from a clean state.
    let _guard = common::BudgetGuard::install(budget);

    // SINGLE-PASS AHO-CORASICK DEX SCAN (v2.0.0):
    // All 9 detector modules used to call `scan_dex_strings` independently,
    // each scanning all DEX strings against their own slice of rules. This
    // required either a 9× redundant scan (slow) OR a thread-local cache
    // holding ALL 1.5M OCTO strings (~75MB heap → lowmemorykiller SIGKILL
    // on Android — the crash regression the user reported).
    //
    // The new `scan_all_dex_once` builds ONE Aho-Corasick automaton from
    // ALL DexString rule patterns across ALL 9 categories, then streams
    // each DEX file's string table through it in a single O(N+M) pass.
    // Peak memory: ~10MB per DEX (transient) vs ~75MB held (constant).
    // Total CPU: ~10× faster than the cached v1.x design.
    //
    // Per-detector scans below now ONLY handle non-DEX evidence
    // (Manifest, NativeLibName, ZipEntry) — DEX scanning is consolidated
    // here.
    let dex_cap = budget.max_dex_files;
    common::scan_all_dex_once(apk, sigs, &mut report.findings, dex_cap);

    // Per-detector scans for non-DEX evidence. Each detector pulls its
    // slice of rules + scans the manifest/native-libs/zip-entries as
    // appropriate. DEX scanning is already done above.
    root::scan(apk, sigs, &mut report.findings);
    play_integrity::scan(apk, sigs, &mut report.findings);
    mtd_rasp::scan(apk, sigs, &mut report.findings);
    app_hardening::scan(apk, sigs, &mut report.findings);
    anti_tamper::scan(apk, sigs, &mut report.findings);
    anti_hooking::scan(apk, sigs, &mut report.findings);
    anti_emulator::scan(apk, sigs, &mut report.findings);
    clone_repackage::scan(apk, sigs, &mut report.findings);
    app_defense::scan(apk, sigs, &mut report.findings);

    // If the AC scanner exhausted the budget, surface it as a Partial outcome.
    if common::budget_exhausted() {
        report.outcome = ScanOutcome::Partial(format!(
            "Scan budget exceeded (max_total_dex_bytes={}, max_dex_files={}). \
             Some DEX files were skipped — findings shown are from DEX files \
             scanned before exhaustion. Increase the budget or split the APK.",
            budget.max_total_dex_bytes, budget.max_dex_files
        ));
    }

    report
}
