//! Detection rule type definitions.
//!
//! Every detection rule across the 8 categories uses the same schema. This
//! makes signatures externally auditable (researchers can PR new YAML rules
//! without touching Rust) and makes the detector logic uniform.

use serde::{Deserialize, Serialize};

/// The 9 detection categories tracked by APK Detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Root detection (su, Magisk, BusyBox, rootBeer-style checks)
    Root,
    /// Play Integrity API usage (classic + standard integrity)
    PlayIntegrity,
    /// MTD / RASP SDKs (Promon, OneSpan, Arxan, Guardsquare, Verimatrix)
    MtdRasp,
    /// App hardening / packers (Bangcle, Ijiami, Qihoo, Tencent Legu, Jiagu)
    AppHardening,
    /// Anti-tamper (signature/self-integrity checks)
    AntiTamper,
    /// Anti-hooking (Frida, Xposed, Substrate, LSPlant)
    AntiHooking,
    /// Anti-emulator (Build.FINGERPRINT, qemu, goldfish, generic checks)
    AntiEmulator,
    /// Clone / repackage detection (app-cloning SDKs, package-name hash)
    CloneRepackage,
    /// App-defense behavior checks — anti-debug, VPN, mock-location,
    /// accessibility-abuse defense, MediaProjection, DRM attestation,
    /// Knox/TIMA, Google Play Services presence, debug-flag checks.
    /// Distinct from AntiTamper (signature/self-integrity) and
    /// AntiHooking (Frida/Xposed): these are runtime *behavior* checks
    /// targeting the user's environment, not the tooling chain.
    AppDefense,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Root => "root",
            Category::PlayIntegrity => "play_integrity",
            Category::MtdRasp => "mtd_rasp",
            Category::AppHardening => "app_hardening",
            Category::AntiTamper => "anti_tamper",
            Category::AntiHooking => "anti_hooking",
            Category::AntiEmulator => "anti_emulator",
            Category::CloneRepackage => "clone_repackage",
            Category::AppDefense => "app_defense",
        }
    }
}

/// Severity bucket. Used by the report renderer for coloring + sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — detection rule is present but impact is low
    Info,
    /// Detects common tooling; bypassable by experienced users
    Low,
    /// Detects default tooling; bypass requires specific knowledge
    Medium,
    /// Detects even custom tooling; bypass requires significant expertise
    High,
    /// Actively blocks the user (kills process, calls home, etc.)
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn emoji(&self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Low => "🟢",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }

    /// Returns true when a finding at this severity would actively **block
    /// or restrict** the user — i.e., the detection criteria are strict
    /// enough that a non-bypassing user cannot use the app normally.
    ///
    /// Threshold: `Medium` and above.
    /// - `Critical` — "Actively blocks the user (kills process, calls home)"
    /// - `High`     — "Detects even custom tooling; bypass requires significant expertise"
    /// - `Medium`   — "Detects default tooling; bypass requires specific knowledge"
    /// - `Low`      — bypassable by experienced users → NOT a block/restrict
    /// - `Info`     — informational only → NOT a block/restrict
    ///
    /// Used by `Report::to_markdown_blocking_only` to filter the report
    /// down to findings that actually impact the user.
    pub fn is_blocking(&self) -> bool {
        matches!(self, Severity::Medium | Severity::High | Severity::Critical)
    }
}

/// Where in the APK to look for the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLocation {
    /// Substring match in any `classes*.dex` string table
    DexString,
    /// Substring match in `AndroidManifest.xml` (binary XML) attrs/values
    Manifest,
    /// Native library filename under `lib/<abi>/`
    NativeLibName,
    /// Native lib contains an ELF symbol matching the pattern
    NativeSymbol,
    /// File path present in the APK ZIP
    ZipEntry,
}

/// One rule. A rule fires if ANY of its `patterns` matches against
/// `evidence_location` data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Stable identifier (kebab-case). Used in reports + bypass hints.
    pub id: String,
    /// Human-readable name shown in the report.
    pub name: String,
    pub category: Category,
    pub severity: Severity,
    /// Where to look.
    pub evidence_location: EvidenceLocation,
    /// One or more case-sensitive substrings (or regex if `is_regex: true`).
    pub patterns: Vec<String>,
    /// If true, `patterns` are interpreted as Rust regex syntax.
    #[serde(default)]
    pub is_regex: bool,
    /// Short note shown in the report (one sentence).
    pub description: String,
    /// Optional bypass-hint key — `BypassHints::lookup(key)` returns the hint text.
    #[serde(default)]
    pub bypass_hint: Option<String>,
}
