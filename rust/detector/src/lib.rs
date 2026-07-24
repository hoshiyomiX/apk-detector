//! # detector
//!
//! 8 detector modules + bypass hints + Markdown report + diff engine.
//!
//! Each detector consumes an `Apk` and a `&SignatureSet`, and produces a
//! list of `Finding` values. The `Report` type aggregates findings across
//! all categories and renders Markdown for the UI.

pub mod anti_emulator;
pub mod anti_hooking;
pub mod anti_tamper;
pub mod app_hardening;
pub mod bypass_hints;
pub mod clone_repackage;
pub mod common;
pub mod diff;
pub mod mtd_rasp;
pub mod play_integrity;
pub mod report;
pub mod root;

pub use report::{Finding, Report, ScanOutcome};
pub use diff::ReportDiff;

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::SignatureSet;

/// Convenience: scan an APK against every category, return a fully-rendered
/// `Report`. The caller is responsible for `apk_path` being a real file
/// (used only for display in the report).
pub fn full_scan<R: Read + Seek>(
    apk_path: &str,
    apk: &mut Apk<R>,
    sigs: &SignatureSet,
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
    report.apk_size_bytes = apk.entries().iter()
        .map(|e| e.uncompressed_size)
        .sum();

    // Run each detector. Each pulls its slice of rules + scans.
    let dex_cap = 10; // first 10 DEX files (multidex safety)
    root::scan(apk, sigs, &mut report.findings, dex_cap);
    play_integrity::scan(apk, sigs, &mut report.findings, dex_cap);
    mtd_rasp::scan(apk, sigs, &mut report.findings, dex_cap);
    app_hardening::scan(apk, sigs, &mut report.findings, dex_cap);
    anti_tamper::scan(apk, sigs, &mut report.findings, dex_cap);
    anti_hooking::scan(apk, sigs, &mut report.findings, dex_cap);
    anti_emulator::scan(apk, sigs, &mut report.findings, dex_cap);
    clone_repackage::scan(apk, sigs, &mut report.findings, dex_cap);

    report
}

