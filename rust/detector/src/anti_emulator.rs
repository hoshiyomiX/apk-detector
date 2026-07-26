//! Anti-emulator scanner. All emulator checks live in DEX.
//!
//! DEX scanning is consolidated in `common::scan_all_dex_once` (called
//! from `lib.rs`). This module's `scan()` is intentionally empty — all
//! anti-emulator rules use `EvidenceLocation::DexString`, so there's no
//! manifest / native-lib / zip-entry work to do here.

use std::io::{Read, Seek};

use apk_parser::Apk;
use signatures::SignatureSet;

use crate::Finding;

pub fn scan<R: Read + Seek>(_apk: &mut Apk<R>, _sigs: &SignatureSet, _findings: &mut Vec<Finding>) {
    // All anti-emulator rules are DexString evidence — handled by
    // `common::scan_all_dex_once` in `lib.rs`. No per-detector work here.
}
