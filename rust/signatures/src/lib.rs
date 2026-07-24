//! # signatures
//!
//! YAML-based detection signatures for the 8 APK defense categories.
//!
//! Each signature is a YAML file under `yaml/*.yaml` with a stable schema.
//! External researchers can PR new signatures without touching Rust code.

pub mod loader;
pub mod types;

pub use loader::{SignatureSet, SignatureSetError};
pub use types::{Category, DetectionRule, EvidenceLocation, Severity};

/// The 8 detection categories tracked by APK Detector.
pub const ALL_CATEGORIES: &[Category] = &[
    Category::Root,
    Category::PlayIntegrity,
    Category::MtdRasp,
    Category::AppHardening,
    Category::AntiTamper,
    Category::AntiHooking,
    Category::AntiEmulator,
    Category::CloneRepackage,
];
