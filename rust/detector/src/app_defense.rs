//! App-defense behavior-check scanner.
//!
//! All 9 rules in this category target `EvidenceLocation::DexString` (the
//! patterns are Android SDK class names / system property keys embedded in
//! the app's bytecode). No manifest or native-lib rules here yet — the
//! OCTO dissection that informed these rules found every pattern in DEX.

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::{Category, EvidenceLocation, SignatureSet};

use crate::common;
use crate::Finding;

pub fn scan<R: Read + Seek>(
    apk: &mut Apk<R>,
    sigs: &SignatureSet,
    findings: &mut Vec<Finding>,
    dex_cap: usize,
) {
    let rules: Vec<_> = sigs
        .by_category(Category::AppDefense)
        .iter()
        .map(|&i| &sigs.rules()[i])
        .collect();
    let dex_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.evidence_location == EvidenceLocation::DexString)
        .copied()
        .collect();
    // No manifest or native-lib rules in this category yet. When added,
    // dispatch them to the appropriate `common::scan_*` helpers.
    let _manifest_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.evidence_location == EvidenceLocation::Manifest)
        .copied()
        .collect();
    common::scan_dex_strings(apk, &dex_rules, findings, dex_cap);
}
