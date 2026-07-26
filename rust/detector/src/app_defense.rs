//! App-defense behavior-check scanner.
//!
//! All 9 rules in this category target `EvidenceLocation::DexString` (the
//! patterns are Android SDK class names / system property keys embedded in
//! the app's bytecode). No manifest or native-lib rules here yet — the
//! OCTO dissection that informed these rules found every pattern in DEX.
//!
//! DEX scanning is consolidated in `common::scan_all_dex_once` (called
//! from `lib.rs`). This module's `scan()` is intentionally empty — there's
//! no per-detector manifest / native-lib / zip-entry work to do here.

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::SignatureSet;

use crate::Finding;

pub fn scan<R: Read + Seek>(_apk: &mut Apk<R>, _sigs: &SignatureSet, _findings: &mut Vec<Finding>) {
    // All app-defense rules are DexString evidence — handled by
    // `common::scan_all_dex_once` in `lib.rs`. No per-detector work here.
}
