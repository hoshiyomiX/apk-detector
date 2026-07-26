//! Clone / repackage scanner. Most clone checks are DEX; some are manifest.

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::{Category, EvidenceLocation, SignatureSet};

use crate::common;
use crate::Finding;

pub fn scan<R: Read + Seek>(apk: &mut Apk<R>, sigs: &SignatureSet, findings: &mut Vec<Finding>) {
    let rules: Vec<_> = sigs
        .by_category(Category::CloneRepackage)
        .iter()
        .map(|&i| &sigs.rules()[i])
        .collect();
    let manifest_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.evidence_location == EvidenceLocation::Manifest)
        .copied()
        .collect();
    let _ = common::scan_manifest(apk, &manifest_rules, findings);
}
