//! # apk-parser
//!
//! Minimal APK reader for the APK Detector project. Extracts just enough
//! information from a target APK to run static detection heuristics:
//!
//! - ZIP central directory enumeration (file list, per-entry size)
//! - `AndroidManifest.xml` binary XML (AXML) decode — enough to read
//!   `<uses-permission>`, `<application>` flags, package name, SDK versions
//! - `classes*.dex` string table scan (substring match against detection rules)
//! - `lib/*/` enumeration (native lib names + ELF arch)
//!
//! All operations are pure-byte: we never execute any code from the target APK.

pub mod apk;
pub mod axml;
pub mod dex;
pub mod elf;
pub mod zip_reader;

pub use apk::{Apk, ApkEntry, ApkError, NativeLib};
pub use axml::{AxmlError, BinaryXml};
pub use dex::DexStringTable;
pub use elf::ElfArch;
