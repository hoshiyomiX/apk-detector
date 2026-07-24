//! Play Integrity scanner. Integrity checks live entirely in DEX — the API
//! is invoked from Java via Play Services bindings.

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
    let dex_rules: Vec<_> = sigs
        .by_category(Category::PlayIntegrity)
        .iter()
        .filter_map(|&i| {
            let r = &sigs.rules()[i];
            (r.evidence_location == EvidenceLocation::DexString).then_some(r)
        })
        .collect();
    common::scan_dex_strings(apk, &dex_rules, findings, dex_cap);
}
