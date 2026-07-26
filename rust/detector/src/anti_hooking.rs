//! Anti-hooking scanner. Frida/Xposed checks live in DEX; native detector
//! libraries (LSPlant, Pine) live in lib/<abi>/.

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::{Category, EvidenceLocation, SignatureSet};

use crate::common;
use crate::Finding;

pub fn scan<R: Read + Seek>(apk: &mut Apk<R>, sigs: &SignatureSet, findings: &mut Vec<Finding>) {
    let rules: Vec<_> = sigs
        .by_category(Category::AntiHooking)
        .iter()
        .map(|&i| &sigs.rules()[i])
        .collect();
    let native_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.evidence_location == EvidenceLocation::NativeLibName)
        .copied()
        .collect();
    let _ = common::scan_native_lib_names(apk, &native_rules, findings);
}
