//! # Device-profile simulator
//!
//! Given a `Report` (scan findings) + a `DeviceProfile` (the target device's
//! relevant attributes), predict which findings would actually TRIGGER on
//! that device and which would be BYPASSED. This answers the user's third
//! question: "Apakah possible APK Scanner melakukan simulasi deteksi sesuai
//! hasil scan target apk dan memberikan result bagian mana saja yang lolos
//! dan bagian mana yang tidak lolos pada device?"
//!
//! ## Design
//!
//! The simulator is a pure function: `simulate(report, profile) -> Report`.
//! For each finding's `rule_id`, we look up a verdict function in the
//! `VERDICT_TABLE`. The verdict function inspects one or more fields on
//! `DeviceProfile` and returns one of:
//!
//! - `Triggered` — the detection would fire on this device; the user CANNOT
//!   use the app unless they change their setup. The verdict includes a
//!   `why` explanation pointing at the specific profile field.
//! - `Bypassed` — the detection rule exists in the APK but the user's
//!   setup defeats it (e.g., Magisk DenyList hides root from a root-check).
//!   Includes `how` explaining how the bypass works.
//! - `Unknown` — no simulator mapping for this rule_id. The verdict
//!   includes a `note` suggesting the user manually verify.
//!
//! ## Presets
//!
//! `DeviceProfile::preset(name)` returns a curated profile for common
//! device classes:
//!
//! - `"clean"` — stock Android, no root, Play Integrity passing, Play
//!   Store installer. Baseline: most defense rules are NOT triggered
//!   (user is "safe").
//! - `"rooted-magisk"` — rooted with Magisk, DenyList ON, Play Integrity
//!   Fix installed. Root checks bypassed; Play Integrity passes.
//! - `"rooted-no-magisk"` — rooted via KingRoot/etc. with no stealth.
//!   Root checks triggered; Play Integrity fails.
//! - `"emulator"` — running on Android Studio emulator. Build.FINGERPRINT
//!   check triggered; telephony checks triggered; sensor checks triggered.
//! - `"frida"` — Frida server running. Anti-hook triggered.
//! - `"dev-options-on"` — Developer Options enabled, USB debugging on.
//!   Anti-debug triggered; debug-flag triggered.
//!
//! ## Output
//!
//! `SimulationReport::to_markdown()` renders a human-readable report.
//! `SimulationReport::to_json()` renders the same data as JSON for
//! programmatic consumption (Kotlin UI, CI integration).

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::report::Finding;
use crate::Report;

/// The user's device environment, as it pertains to defense-rule evaluation.
///
/// Fields are `Option<bool>` rather than `bool` because the user may not
/// know / may not have tested every attribute. `None` means "unknown" —
/// the simulator returns `SimulationVerdict::Unknown` for any rule whose
/// verdict depends on an unknown field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceProfile {
    /// Device is rooted (any root impl — Magisk, KernelSU, KingRoot, ...).
    pub rooted: Option<bool>,
    /// Magisk DenyList (or Shamiko) is ON for the target app's package.
    /// When true, root checks see an unrooted environment.
    pub magisk_denylist_on: Option<bool>,
    /// Play Integrity API verdict: `true` if device passes
    /// `DEVICE_INTEGRITY` + `BASIC_INTEGRITY`.
    pub play_integrity_passes: Option<bool>,
    /// SafetyNet attestation verdict (legacy API). `true` if passes CTS
    /// profile match.
    pub safetynet_passes: Option<bool>,
    /// App was installed from Google Play Store
    /// (`com.android.vending`). `false` if sideloaded or installed
    /// from a third-party store.
    pub installer_is_play_store: Option<bool>,
    /// App was installed via a clone/dual-space runtime
    /// (Parallel Space, VirtualApp, etc.).
    pub in_clone_runtime: Option<bool>,
    /// Device is running on an Android emulator (AVD, BlueStacks, Nox).
    pub is_emulator: Option<bool>,
    /// Frida server / gadget is running in the target process.
    pub frida_running: Option<bool>,
    /// Xposed framework is loaded.
    pub xposed_loaded: Option<bool>,
    /// Mock location provider is enabled (Location.isFromMockProvider()).
    pub mock_location_on: Option<bool>,
    /// A VPN tunnel is active (tun0 interface present).
    pub vpn_active: Option<bool>,
    /// A debugger is attached (Debug.isDebuggerConnected() == true).
    pub debugger_attached: Option<bool>,
    /// Developer Options + USB debugging are enabled.
    pub developer_options_on: Option<bool>,
    /// An accessibility service is enabled (other than system ones).
    pub accessibility_service_on: Option<bool>,
    /// A MediaProjection session is active (screen recording).
    pub media_projection_active: Option<bool>,
    /// Google Play Services is installed and available.
    pub play_services_available: Option<bool>,
    /// Device is a Samsung with KNOX / TIMA available.
    pub is_samsung_knox: Option<bool>,
    /// Widevine DRM attestation returns L1 (hardware-backed).
    pub widevine_l1: Option<bool>,
    /// The APK has been repackaged (signature mismatch with original).
    pub repackaged: Option<bool>,
    /// App's self-integrity check would FAIL (file tampered).
    pub self_integrity_broken: Option<bool>,
}

impl DeviceProfile {
    /// Return one of the curated preset profiles. Returns `None` if the
    /// name is not recognized.
    pub fn preset(name: &str) -> Option<Self> {
        Some(match name {
            "clean" => Self {
                rooted: Some(false),
                magisk_denylist_on: Some(false),
                play_integrity_passes: Some(true),
                safetynet_passes: Some(true),
                installer_is_play_store: Some(true),
                in_clone_runtime: Some(false),
                is_emulator: Some(false),
                frida_running: Some(false),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(false),
                developer_options_on: Some(false),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false),
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            "rooted-magisk" => Self {
                rooted: Some(true),
                magisk_denylist_on: Some(true),
                play_integrity_passes: Some(true), // via Play Integrity Fix module
                safetynet_passes: Some(true),
                installer_is_play_store: Some(true),
                in_clone_runtime: Some(false),
                is_emulator: Some(false),
                frida_running: Some(false),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(false),
                developer_options_on: Some(false),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false),
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            "rooted-no-magisk" => Self {
                rooted: Some(true),
                magisk_denylist_on: Some(false),
                play_integrity_passes: Some(false),
                safetynet_passes: Some(false),
                installer_is_play_store: Some(true),
                in_clone_runtime: Some(false),
                is_emulator: Some(false),
                frida_running: Some(false),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(false),
                developer_options_on: Some(false),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false),
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            "emulator" => Self {
                rooted: Some(false),
                magisk_denylist_on: Some(false),
                play_integrity_passes: Some(false),
                safetynet_passes: Some(false),
                installer_is_play_store: Some(false),
                in_clone_runtime: Some(false),
                is_emulator: Some(true),
                frida_running: Some(false),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(true), // emulator usually runs with debugger
                developer_options_on: Some(true),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false), // emulator usually L3
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            "frida" => Self {
                rooted: Some(false),
                magisk_denylist_on: Some(false),
                play_integrity_passes: Some(true),
                safetynet_passes: Some(true),
                installer_is_play_store: Some(true),
                in_clone_runtime: Some(false),
                is_emulator: Some(false),
                frida_running: Some(true),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(false),
                developer_options_on: Some(false),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false),
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            "dev-options-on" => Self {
                rooted: Some(false),
                magisk_denylist_on: Some(false),
                play_integrity_passes: Some(true),
                safetynet_passes: Some(true),
                installer_is_play_store: Some(true),
                in_clone_runtime: Some(false),
                is_emulator: Some(false),
                frida_running: Some(false),
                xposed_loaded: Some(false),
                mock_location_on: Some(false),
                vpn_active: Some(false),
                debugger_attached: Some(true),
                developer_options_on: Some(true),
                accessibility_service_on: Some(false),
                media_projection_active: Some(false),
                play_services_available: Some(true),
                is_samsung_knox: Some(false),
                widevine_l1: Some(false),
                repackaged: Some(false),
                self_integrity_broken: Some(false),
            },
            _ => return None,
        })
    }

    /// Serialize to a compact JSON string. Used by the JNI bridge + CLI for
    /// passing the profile across FFI boundaries.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        let mut first = true;
        let push = |s: &mut String, key: &str, v: Option<bool>, first: &mut bool| {
            if let Some(b) = v {
                if !*first {
                    s.push(',');
                }
                *first = false;
                s.push_str(&format!("\"{}\":{}", key, b));
            }
        };
        push(&mut s, "rooted", self.rooted, &mut first);
        push(
            &mut s,
            "magisk_denylist_on",
            self.magisk_denylist_on,
            &mut first,
        );
        push(
            &mut s,
            "play_integrity_passes",
            self.play_integrity_passes,
            &mut first,
        );
        push(
            &mut s,
            "safetynet_passes",
            self.safetynet_passes,
            &mut first,
        );
        push(
            &mut s,
            "installer_is_play_store",
            self.installer_is_play_store,
            &mut first,
        );
        push(
            &mut s,
            "in_clone_runtime",
            self.in_clone_runtime,
            &mut first,
        );
        push(&mut s, "is_emulator", self.is_emulator, &mut first);
        push(&mut s, "frida_running", self.frida_running, &mut first);
        push(&mut s, "xposed_loaded", self.xposed_loaded, &mut first);
        push(
            &mut s,
            "mock_location_on",
            self.mock_location_on,
            &mut first,
        );
        push(&mut s, "vpn_active", self.vpn_active, &mut first);
        push(
            &mut s,
            "debugger_attached",
            self.debugger_attached,
            &mut first,
        );
        push(
            &mut s,
            "developer_options_on",
            self.developer_options_on,
            &mut first,
        );
        push(
            &mut s,
            "accessibility_service_on",
            self.accessibility_service_on,
            &mut first,
        );
        push(
            &mut s,
            "media_projection_active",
            self.media_projection_active,
            &mut first,
        );
        push(
            &mut s,
            "play_services_available",
            self.play_services_available,
            &mut first,
        );
        push(&mut s, "is_samsung_knox", self.is_samsung_knox, &mut first);
        push(&mut s, "widevine_l1", self.widevine_l1, &mut first);
        push(&mut s, "repackaged", self.repackaged, &mut first);
        push(
            &mut s,
            "self_integrity_broken",
            self.self_integrity_broken,
            &mut first,
        );
        s.push('}');
        s
    }

    /// Parse a JSON profile string. Tolerant: unknown keys are ignored,
    /// missing keys default to `None`. Returns `Err(message)` on malformed
    /// JSON (unclosed braces, bad bool literal, etc.).
    pub fn from_json(json: &str) -> Result<Self, String> {
        let trimmed = json.trim();
        if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
            return Err(format!("profile JSON must be a single object: {}", trimmed));
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut p = Self::default();
        for entry in split_top_level(inner) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let colon = match entry.find(':') {
                Some(i) => i,
                None => return Err(format!("missing ':' in entry: {}", entry)),
            };
            let raw_key = entry[..colon].trim();
            let val = entry[colon + 1..].trim();
            // Strict JSON: keys must be double-quoted. Reject unquoted keys
            // (e.g. `{rooted:true}`) so malformed input is surfaced, not
            // silently accepted. `trim_matches('"')` is only applied AFTER
            // the quote-presence check.
            if !(raw_key.starts_with('"') && raw_key.ends_with('"') && raw_key.len() >= 2) {
                return Err(format!("JSON keys must be double-quoted: `{}`", raw_key));
            }
            let key = &raw_key[1..raw_key.len() - 1];
            let b = match val {
                "true" => Some(true),
                "false" => Some(false),
                "null" => None,
                _ => return Err(format!("bad bool value: {} = {}", key, val)),
            };
            match key {
                "rooted" => p.rooted = b,
                "magisk_denylist_on" => p.magisk_denylist_on = b,
                "play_integrity_passes" => p.play_integrity_passes = b,
                "safetynet_passes" => p.safetynet_passes = b,
                "installer_is_play_store" => p.installer_is_play_store = b,
                "in_clone_runtime" => p.in_clone_runtime = b,
                "is_emulator" => p.is_emulator = b,
                "frida_running" => p.frida_running = b,
                "xposed_loaded" => p.xposed_loaded = b,
                "mock_location_on" => p.mock_location_on = b,
                "vpn_active" => p.vpn_active = b,
                "debugger_attached" => p.debugger_attached = b,
                "developer_options_on" => p.developer_options_on = b,
                "accessibility_service_on" => p.accessibility_service_on = b,
                "media_projection_active" => p.media_projection_active = b,
                "play_services_available" => p.play_services_available = b,
                "is_samsung_knox" => p.is_samsung_knox = b,
                "widevine_l1" => p.widevine_l1 = b,
                "repackaged" => p.repackaged = b,
                "self_integrity_broken" => p.self_integrity_broken = b,
                _ => { /* unknown key — tolerant parse */ }
            }
        }
        Ok(p)
    }
}

/// Split a comma-separated JSON object body on top-level commas only
/// (commas inside nested objects/arrays are not split — though we don't
/// have nested structures in the profile schema, this is defensive).
fn split_top_level(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Per-finding simulator verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationVerdict {
    /// The detection WOULD fire on this device — the user cannot use the
    /// app unless they change their setup or apply a bypass.
    Triggered { why: String },
    /// The detection rule is present in the APK but the user's setup
    /// defeats it.
    Bypassed { how: String },
    /// No simulator mapping for this rule_id, or the relevant profile
    /// fields are unset (None).
    Unknown { note: String },
}

/// One finding + its simulator verdict.
#[derive(Debug, Clone)]
pub struct SimulationEntry {
    pub finding: Finding,
    pub verdict: SimulationVerdict,
}

/// The complete simulation result for a scan + profile pair.
#[derive(Debug, Clone)]
pub struct SimulationReport {
    pub apk_path: String,
    pub profile_json: String,
    pub entries: Vec<SimulationEntry>,
    pub engine_version: &'static str,
}

impl SimulationReport {
    /// Counts for the summary table.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut triggered = 0;
        let mut bypassed = 0;
        let mut unknown = 0;
        for e in &self.entries {
            match e.verdict {
                SimulationVerdict::Triggered { .. } => triggered += 1,
                SimulationVerdict::Bypassed { .. } => bypassed += 1,
                SimulationVerdict::Unknown { .. } => unknown += 1,
            }
        }
        (triggered, bypassed, unknown)
    }

    /// Render the simulation as Markdown. Layout mirrors `Report::to_markdown`
    /// for consistency with the existing UI renderer.
    pub fn to_markdown(&self) -> String {
        let mut md = String::with_capacity(8 * 1024);
        let _ = writeln!(md, "# APK Detector — Device Simulation Report");
        let _ = writeln!(md);
        let _ = writeln!(md, "**Engine:** APK Detector v{}", self.engine_version);
        let _ = writeln!(md, "**Target APK:** `{}`", self.apk_path);
        let _ = writeln!(md, "**Device profile:** `{}`", self.profile_json);
        let (triggered, bypassed, unknown) = self.counts();
        let total = self.entries.len();
        let _ = writeln!(
            md,
            "**Findings:** {} total — {} triggered, {} bypassed, {} unknown",
            total, triggered, bypassed, unknown
        );
        let _ = writeln!(md);

        // Summary by verdict
        let _ = writeln!(md, "## Summary");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Verdict | Count | Meaning |");
        let _ = writeln!(md, "|---|---:|---|");
        let _ = writeln!(
            md,
            "| 🔴 Triggered | {} | Detection fires on this device — user is blocked/restricted |",
            triggered
        );
        let _ = writeln!(
            md,
            "| 🟢 Bypassed  | {} | Detection rule exists but user's setup defeats it |",
            bypassed
        );
        let _ = writeln!(
            md,
            "| ⚪ Unknown   | {} | Simulator has no mapping, or profile field is unset |",
            unknown
        );
        let _ = writeln!(md);

        // Per-verdict detail sections
        let _ = writeln!(md, "## Detailed Simulation");
        let _ = writeln!(md);

        if triggered > 0 {
            let _ = writeln!(
                md,
                "### 🔴 Triggered ({} finding{})",
                triggered,
                plural_s(triggered)
            );
            let _ = writeln!(md);
            for e in &self.entries {
                if let SimulationVerdict::Triggered { why } = &e.verdict {
                    let _ = writeln!(
                        md,
                        "**{} {}** `{}`",
                        e.finding.severity.emoji(),
                        e.finding.severity.as_str().to_uppercase(),
                        e.finding.rule_id
                    );
                    let _ = writeln!(md, ": {}", e.finding.rule_name);
                    let _ = writeln!(md);
                    let _ = writeln!(md, "- Why it triggers: {}", why);
                    if let Some(hint_key) = &e.finding.bypass_hint_key {
                        if let Some(hint) = crate::bypass_hints::lookup(hint_key) {
                            let _ = writeln!(md, "- **Bypass hint:** {}", hint);
                        }
                    }
                    let _ = writeln!(md);
                }
            }
        }

        if bypassed > 0 {
            let _ = writeln!(
                md,
                "### 🟢 Bypassed ({} finding{})",
                bypassed,
                plural_s(bypassed)
            );
            let _ = writeln!(md);
            for e in &self.entries {
                if let SimulationVerdict::Bypassed { how } = &e.verdict {
                    let _ = writeln!(
                        md,
                        "**{} {}** `{}`",
                        e.finding.severity.emoji(),
                        e.finding.severity.as_str().to_uppercase(),
                        e.finding.rule_id
                    );
                    let _ = writeln!(md, ": {}", e.finding.rule_name);
                    let _ = writeln!(md);
                    let _ = writeln!(md, "- How it's bypassed: {}", how);
                    let _ = writeln!(md);
                }
            }
        }

        if unknown > 0 {
            let _ = writeln!(
                md,
                "### ⚪ Unknown ({} finding{})",
                unknown,
                plural_s(unknown)
            );
            let _ = writeln!(md);
            for e in &self.entries {
                if let SimulationVerdict::Unknown { note } = &e.verdict {
                    let _ = writeln!(
                        md,
                        "**{} {}** `{}`",
                        e.finding.severity.emoji(),
                        e.finding.severity.as_str().to_uppercase(),
                        e.finding.rule_id
                    );
                    let _ = writeln!(md, ": {}", e.finding.rule_name);
                    let _ = writeln!(md);
                    let _ = writeln!(md, "- Note: {}", note);
                    let _ = writeln!(md);
                }
            }
        }

        if total == 0 {
            let _ = writeln!(
                md,
                "_No findings to simulate — the scan produced no detections._"
            );
            let _ = writeln!(md);
        }

        md
    }

    /// Render the simulation as JSON. Suitable for machine consumption.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        let _ = write!(s, "\"apk_path\":\"{}\",", json_escape(&self.apk_path));
        let _ = write!(s, "\"profile\":{},", self.profile_json);
        let _ = write!(s, "\"engine_version\":\"{}\",", self.engine_version);
        let (triggered, bypassed, unknown) = self.counts();
        let _ = write!(
            s,
            "\"summary\":{{\"triggered\":{},\"bypassed\":{},\"unknown\":{},\"total\":{}}},",
            triggered,
            bypassed,
            unknown,
            self.entries.len()
        );
        s.push_str("\"entries\":[");
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&entry_to_json(e));
        }
        s.push(']');
        s.push('}');
        s
    }
}

fn entry_to_json(e: &SimulationEntry) -> String {
    let mut s = String::from("{");
    let _ = write!(s, "\"rule_id\":\"{}\",", json_escape(&e.finding.rule_id));
    let _ = write!(
        s,
        "\"rule_name\":\"{}\",",
        json_escape(&e.finding.rule_name)
    );
    let _ = write!(s, "\"category\":\"{}\",", e.finding.category.as_str());
    let _ = write!(s, "\"severity\":\"{}\",", e.finding.severity.as_str());
    let _ = write!(s, "\"evidence\":\"{}\",", json_escape(&e.finding.evidence));
    let (verdict_label, verdict_detail) = match &e.verdict {
        SimulationVerdict::Triggered { why } => ("triggered", why.clone()),
        SimulationVerdict::Bypassed { how } => ("bypassed", how.clone()),
        SimulationVerdict::Unknown { note } => ("unknown", note.clone()),
    };
    let _ = write!(s, "\"verdict\":\"{}\",", verdict_label);
    let _ = write!(s, "\"detail\":\"{}\"", json_escape(&verdict_detail));
    s.push('}');
    s
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn plural_s(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Run the simulator over a scan report + device profile.
pub fn simulate(report: &Report, profile: &DeviceProfile) -> SimulationReport {
    let table = verdict_table();
    let entries: Vec<SimulationEntry> = report
        .findings
        .iter()
        .map(|f| {
            let verdict = match table.get(f.rule_id.as_str()) {
                Some(vfn) => vfn(profile),
                None => SimulationVerdict::Unknown {
                    note: format!(
                        "no simulator mapping for rule_id `{}` — manually verify against the device",
                        f.rule_id
                    ),
                },
            };
            SimulationEntry {
                finding: f.clone(),
                verdict,
            }
        })
        .collect();
    SimulationReport {
        apk_path: report.apk_path.clone(),
        profile_json: profile.to_json(),
        entries,
        engine_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Verdict-function type: takes a profile, returns a verdict.
type VerdictFn = fn(&DeviceProfile) -> SimulationVerdict;

/// Build the rule_id → verdict-function table. Kept as a function (not a
/// `const`) because `HashMap::from` isn't const-evaluable yet on stable.
fn verdict_table() -> HashMap<&'static str, VerdictFn> {
    let mut m: HashMap<&'static str, VerdictFn> = HashMap::with_capacity(48);
    // ---- Root detection -----------------------------------------------------
    m.insert("root-check-su-binary", |p: &DeviceProfile| {
        match (p.rooted, p.magisk_denylist_on) {
            (Some(false), _) => SimulationVerdict::Bypassed {
                how: "Device is not rooted — su binary does not exist.".to_string(),
            },
            (Some(true), Some(true)) => SimulationVerdict::Bypassed {
                how: "Magisk DenyList hides the su binary + Magisk's mount namespaces from this process.".to_string(),
            },
            (Some(true), Some(false)) => SimulationVerdict::Triggered {
                why: "Device is rooted and DenyList is OFF — the su binary is visible at /system/bin/su or /system/xbin/su.".to_string(),
            },
            (Some(true), None) | (None, _) => SimulationVerdict::Unknown {
                note: "Need both `rooted` and `magisk_denylist_on` profile fields to evaluate.".to_string(),
            },
        }
    });
    m.insert("root-check-ro-secure-prop", |p: &DeviceProfile| {
        match p.rooted {
            Some(false) => SimulationVerdict::Bypassed {
                how: "ro.secure=1 on stock builds — check does not fire.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Rooted builds often flip ro.secure=0 or ro.debuggable=1, which this check detects.".to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `rooted` in profile.".to_string(),
            },
        }
    });
    m.insert("root-magisk-binary", |p: &DeviceProfile| {
        match (p.rooted, p.magisk_denylist_on) {
            (Some(false), _) => SimulationVerdict::Bypassed {
                how: "No Magisk installed.".to_string(),
            },
            (Some(true), Some(true)) => SimulationVerdict::Bypassed {
                how:
                    "Magisk DenyList hides the magisk binary + its mount points from this process."
                        .to_string(),
            },
            (Some(true), Some(false)) => SimulationVerdict::Triggered {
                why: "Magisk binary visible in PATH or /sbin — DenyList is OFF.".to_string(),
            },
            _ => SimulationVerdict::Unknown {
                note: "Need `rooted` + `magisk_denylist_on`.".to_string(),
            },
        }
    });
    m.insert("root-busybox-binary", |p: &DeviceProfile| match p.rooted {
        Some(false) => SimulationVerdict::Bypassed {
            how: "BusyBox not present on stock builds.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Rooted devices usually have BusyBox installed at /system/xbin/busybox."
                .to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `rooted` in profile.".to_string(),
        },
    });
    m.insert("root-check-su-vending", |p: &DeviceProfile| {
        match p.rooted {
            Some(false) => SimulationVerdict::Bypassed {
                how: "No Superuser.apk on stock builds.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Superuser.apk present at /system/app/Superuser.apk.".to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `rooted` in profile.".to_string(),
            },
        }
    });
    m.insert("root-test-keys-build", |p: &DeviceProfile| match p.rooted {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Stock release-keys build — ro.build.tags does not contain test-keys.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Custom ROM builds usually carry test-keys in ro.build.tags.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `rooted` in profile.".to_string(),
        },
    });

    // ---- Play Integrity -----------------------------------------------------
    m.insert("play-integrity-api-call", |p: &DeviceProfile| match p.play_integrity_passes {
        Some(true) => SimulationVerdict::Bypassed {
            how: "Device passes Play Integrity (Play Integrity Fix module or stock device). API returns DEVICE_INTEGRITY.".to_string(),
        },
        Some(false) => SimulationVerdict::Triggered {
            why: "Play Integrity API call returns a verdict missing DEVICE_INTEGRITY — app rejects.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `play_integrity_passes` in profile.".to_string(),
        },
    });
    m.insert("play-integrity-manager-impl", |p: &DeviceProfile| {
        match p.play_integrity_passes {
            Some(true) => SimulationVerdict::Bypassed {
                how:
                    "Integrity token decodes cleanly — device-integrity + app-integrity both pass."
                        .to_string(),
            },
            Some(false) => SimulationVerdict::Triggered {
                why: "Token verification fails — IntegrityTokenResponse carries an error verdict."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `play_integrity_passes` in profile.".to_string(),
            },
        }
    });
    m.insert(
        "play-integrity-safety-net-legacy",
        |p: &DeviceProfile| match p.safetynet_passes {
            Some(true) => SimulationVerdict::Bypassed {
                how: "SafetyNet attestation passes CTS profile match.".to_string(),
            },
            Some(false) => SimulationVerdict::Triggered {
                why:
                    "SafetyNet returns BASIC_INTTEGRITY but fails CTS_PROFILE_MATCH — app rejects."
                        .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `safetynet_passes` in profile.".to_string(),
            },
        },
    );

    // ---- MTD / RASP ---------------------------------------------------------
    m.insert("mtd-rasp-promon-shield", |p: &DeviceProfile| match (p.frida_running, p.xposed_loaded, p.rooted) {
        (Some(false), Some(false), Some(false)) => SimulationVerdict::Bypassed {
            how: "No instrumentation detected — Promon's runtime checks pass.".to_string(),
        },
        (Some(true), _, _) | (_, Some(true), _) | (_, _, Some(true)) => SimulationVerdict::Triggered {
            why: "Promon SHIELD detects Frida/Xposed/root at the native layer and calls abort().".to_string(),
        },
        _ => SimulationVerdict::Unknown {
            note: "Need `frida_running` + `xposed_loaded` + `rooted`.".to_string(),
        },
    });
    m.insert("mtd-rasp-onespan", |p: &DeviceProfile| {
        match (p.frida_running, p.xposed_loaded) {
            (Some(false), Some(false)) => SimulationVerdict::Bypassed {
                how: "No instrumentation detected — OneSpan runtime checks pass.".to_string(),
            },
            (Some(true), _) | (_, Some(true)) => SimulationVerdict::Triggered {
                why: "OneSpan detects active instrumentation and exits.".to_string(),
            },
            _ => SimulationVerdict::Unknown {
                note: "Need `frida_running` + `xposed_loaded`.".to_string(),
            },
        }
    });
    m.insert("mtd-rasp-arxan", |p: &DeviceProfile| {
        match p.frida_running {
            Some(false) => SimulationVerdict::Bypassed {
                how: "No Frida detected — Arxan's anti-tamper checks pass.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Arxan's Frida detection fires (code-obfuscation + integrity check)."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `frida_running` in profile.".to_string(),
            },
        }
    });
    m.insert("mtd-rasp-guardsquare", |p: &DeviceProfile| {
        match p.frida_running {
            Some(false) => SimulationVerdict::Bypassed {
                how: "No Frida detected — Guardsquare DexGuard runtime passes.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "DexGuard detects Frida via /proc/self/maps scan.".to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `frida_running` in profile.".to_string(),
            },
        }
    });
    m.insert("mtd-rasp-verimatrix", |p: &DeviceProfile| {
        match p.frida_running {
            Some(false) => SimulationVerdict::Bypassed {
                how: "No Frida detected — Verimatrix runtime passes.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Verimatrix detects active instrumentation.".to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `frida_running` in profile.".to_string(),
            },
        }
    });

    // ---- App hardening (packers) -------------------------------------------
    // Packers don't "trigger" against a device — they're an APK-side
    // protection. From the simulator's perspective they are always
    // `Bypassed` on a clean device (the packer runs successfully, the app
    // works) and `Unknown` if the device profile is incompatible with the
    // packer's runtime requirements (rare — packers are designed to run
    // on stock Android).
    m.insert("hardening-bangcle", |_: &DeviceProfile| SimulationVerdict::Bypassed {
        how: "Bangcle packer unpacks DEX at runtime on any compatible Android — no device-side trigger.".to_string(),
    });
    m.insert("hardening-bangcle-java", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "Bangcle Java loader runs on any Android — no device-side trigger.".to_string(),
        }
    });
    m.insert("hardening-ijiami", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "Ijiami packer runs on any Android — no device-side trigger.".to_string(),
        }
    });
    m.insert("hardening-qihoo-360", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "Qihoo 360 Jiagu runs on any Android — no device-side trigger.".to_string(),
        }
    });
    m.insert("hardening-tencent-legu", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "Tencent Legu runs on any Android — no device-side trigger.".to_string(),
        }
    });
    m.insert("hardening-tencent-legu-java", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "Tencent Legu Java entry runs on any Android — no device-side trigger."
                .to_string(),
        }
    });
    m.insert("hardening-naga-ali", |_: &DeviceProfile| {
        SimulationVerdict::Bypassed {
            how: "NAGA/Ali packer runs on any Android — no device-side trigger.".to_string(),
        }
    });

    // ---- Anti-tamper --------------------------------------------------------
    m.insert("anti-tamper-pm-get-signatures-v2", |p: &DeviceProfile| match p.repackaged {
        Some(false) => SimulationVerdict::Bypassed {
            how: "APK signature matches the original — PackageManager.getSigningInfo() returns the expected cert.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "APK was repackaged — signing certificate mismatch detected via GET_SIGNING_CERTIFICATES.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `repackaged` in profile.".to_string(),
        },
    });
    m.insert("anti-tamper-self-integrity", |p: &DeviceProfile| match p.self_integrity_broken {
        Some(false) => SimulationVerdict::Bypassed {
            how: "APK file hash matches the expected value — self-integrity check passes.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "APK file has been modified — runtime hash differs from expected, self-integrity fails.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `self_integrity_broken` in profile.".to_string(),
        },
    });
    m.insert("anti-tamper-signature-get-installed", |p: &DeviceProfile| match p.repackaged {
        Some(false) => SimulationVerdict::Bypassed {
            how: "getInstalledPackages returns the original signature — check passes.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Repackaged APK's signature differs from the original — PackageManager.getPackageInfo(GET_SIGNATURES) catches the mismatch.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `repackaged` in profile.".to_string(),
        },
    });
    m.insert("anti-tamper-dex-crc", |p: &DeviceProfile| match p.self_integrity_broken {
        Some(false) => SimulationVerdict::Bypassed {
            how: "DEX CRC matches the value stored in the DEX header — check passes.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "DEX bytecode modified — runtime Adler32 differs from the DEX header's checksum field.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `self_integrity_broken` in profile.".to_string(),
        },
    });

    // ---- Anti-hooking -------------------------------------------------------
    m.insert("anti-hook-frida-maps-scan", |p: &DeviceProfile| match p.frida_running {
        Some(false) => SimulationVerdict::Bypassed {
            how: "No Frida agent loaded — /proc/self/maps contains no frida-agent.so entry.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Frida agent mapped into process memory — /proc/self/maps scan finds frida-agent.so or gum-js-loop.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `frida_running` in profile.".to_string(),
        },
    });
    m.insert(
        "anti-hook-frida-default-port",
        |p: &DeviceProfile| match p.frida_running {
            Some(false) => SimulationVerdict::Bypassed {
                how: "No Frida server listening on default port 27042.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Frida server is running on port 27042 (or whatever port the rule scans)."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `frida_running` in profile.".to_string(),
            },
        },
    );
    m.insert("anti-hook-xposed-impl", |p: &DeviceProfile| {
        match p.xposed_loaded {
            Some(false) => SimulationVerdict::Bypassed {
                how: "Xposed framework not loaded — no Xposed bridge in process.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Xposed framework loaded — de.robv.android.xposed.XposedBridge is resolvable."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `xposed_loaded` in profile.".to_string(),
            },
        }
    });

    // ---- Anti-emulator ------------------------------------------------------
    m.insert("anti-emulator-build-fingerprint", |p: &DeviceProfile| match p.is_emulator {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Build.FINGERPRINT is a real device string (e.g. samsung/star2q5g/x1q...).".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Build.FINGERPRINT contains emulator markers (generic_x86, sdk_gphone, google_sdk, ...).".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `is_emulator` in profile.".to_string(),
        },
    });
    m.insert(
        "anti-emulator-build-manufacturer",
        |p: &DeviceProfile| match p.is_emulator {
            Some(false) => SimulationVerdict::Bypassed {
                how: "Build.MANUFACTURER/BRAND/HARDWARE/MODEL are real-device values.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why:
                    "Build.* fields carry emulator defaults (unknown, google, goldfish_arm64, ...)."
                        .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `is_emulator` in profile.".to_string(),
            },
        },
    );
    m.insert("anti-emulator-files", |p: &DeviceProfile| match p.is_emulator {
        Some(false) => SimulationVerdict::Bypassed {
            how: "/dev/socket/qemud, /dev/qemu_pipe, etc. do not exist on real devices.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Emulator-only filesystem paths exist (qemud socket, qemu_pipe, libc_malloc_debug_qemu.so).".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `is_emulator` in profile.".to_string(),
        },
    });
    m.insert("anti-emulator-network", |p: &DeviceProfile| {
        match p.is_emulator {
            Some(false) => SimulationVerdict::Bypassed {
                how:
                    "Network interfaces do not include emulator defaults (10.0.2.15, eth0 routing)."
                        .to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Emulator network probes return default values (10.0.2.15 IP, eth0 iface)."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `is_emulator` in profile.".to_string(),
            },
        }
    });
    m.insert("anti-emulator-telephony", |p: &DeviceProfile| {
        match p.is_emulator {
            Some(false) => SimulationVerdict::Bypassed {
                how: "TelephonyManager returns real device values.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "TelephonyManager.getDeviceId() returns emulator dummy (15555215554, null)."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `is_emulator` in profile.".to_string(),
            },
        }
    });
    m.insert("anti-emulator-sensors", |p: &DeviceProfile| match p.is_emulator {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Real accelerometers / gyroscopes are present and return non-default values.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Emulator sensors are absent or return constant values (TYPE_ACCELEROMETER reports 0.0).".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `is_emulator` in profile.".to_string(),
        },
    });
    m.insert("anti-emulator-bluestacks", |p: &DeviceProfile| {
        match p.is_emulator {
            Some(false) => SimulationVerdict::Bypassed {
                how: "DMI sys_vendor does not match BlueStacks/Nox/LDPlayer signatures."
                    .to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "/sys/class/dmi/id/sys_vendor matches BlueStacks/Nox/LDPlayer vendor strings."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `is_emulator` in profile.".to_string(),
            },
        }
    });

    // ---- Clone / repackage --------------------------------------------------
    m.insert("clone-installer-source", |p: &DeviceProfile| match p.installer_is_play_store {
        Some(true) => SimulationVerdict::Bypassed {
            how: "getInstallerPackageName() returns com.android.vending — installed from Play Store.".to_string(),
        },
        Some(false) => SimulationVerdict::Triggered {
            why: "getInstallerPackageName() returns null or a non-Play installer — sideloaded clone suspected.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `installer_is_play_store` in profile.".to_string(),
        },
    });
    m.insert("clone-parallel-space", |p: &DeviceProfile| match p.in_clone_runtime {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Not running inside Parallel Space / Dual Space — package list does not contain com.lbe.parallel.*.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Running inside Parallel Space / Dual Space — host package visible to the guest process.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `in_clone_runtime` in profile.".to_string(),
        },
    });
    m.insert("clone-virtualapp", |p: &DeviceProfile| match p.in_clone_runtime {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Not running inside VirtualApp — VirtualCore / VClient not present.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "VirtualApp runtime detected — io.virtualapp / com.lody.virtual.* classes loaded.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `in_clone_runtime` in profile.".to_string(),
        },
    });
    m.insert(
        "clone-package-name-self-check",
        |p: &DeviceProfile| match p.repackaged {
            Some(false) => SimulationVerdict::Bypassed {
                how: "getPackageName() matches the hardcoded original — no rename occurred."
                    .to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why:
                    "APK was repackaged under a different package name — getPackageName() mismatch."
                        .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `repackaged` in profile.".to_string(),
            },
        },
    );
    m.insert("clone-meta-data-marker", |p: &DeviceProfile| {
        match p.repackaged {
            Some(false) => SimulationVerdict::Bypassed {
                how: "Manifest has no clone/repackaged marker meta-data.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Manifest carries a clone marker (CLONE_MARKER / REPACKAGED_FLAG meta-data)."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `repackaged` in profile.".to_string(),
            },
        }
    });

    // ---- App defense (new category) ----------------------------------------
    m.insert("app-defense-anti-debug", |p: &DeviceProfile| match p.debugger_attached {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Debug.isDebuggerConnected() returns false and /proc/self/status TracerPid is 0.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Debugger attached — Debug.isDebuggerConnected() == true OR TracerPid != 0 in /proc/self/status.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `debugger_attached` in profile.".to_string(),
        },
    });
    m.insert("app-defense-debug-flag", |p: &DeviceProfile| match p.developer_options_on {
        Some(false) => SimulationVerdict::Bypassed {
            how: "Settings.Global.ADB_ENABLED=0 and DEVELOPMENT_SETTINGS_ENABLED=0.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Developer options enabled — Settings.Global.ADB_ENABLED=1 OR DEVELOPMENT_SETTINGS_ENABLED=1.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `developer_options_on` in profile.".to_string(),
        },
    });
    m.insert("app-defense-vpn", |p: &DeviceProfile| match p.vpn_active {
        Some(false) => SimulationVerdict::Bypassed {
            how: "No tun0/tun1 interface present — NetworkCapabilities has no TRANSPORT_VPN.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Active VPN tunnel — tun0 interface up or NetworkCapabilities.TRANSPORT_VPN present.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `vpn_active` in profile.".to_string(),
        },
    });
    m.insert("app-defense-mock-location", |p: &DeviceProfile| {
        match p.mock_location_on {
            Some(false) => SimulationVerdict::Bypassed {
                how: "Location.isFromMockProvider() returns false for all locations.".to_string(),
            },
            Some(true) => SimulationVerdict::Triggered {
                why: "Mock location provider enabled — Location.isFromMockProvider() returns true."
                    .to_string(),
            },
            None => SimulationVerdict::Unknown {
                note: "Set `mock_location_on` in profile.".to_string(),
            },
        }
    });
    m.insert("app-defense-accessibility", |p: &DeviceProfile| match p.accessibility_service_on {
        Some(false) => SimulationVerdict::Bypassed {
            how: "No non-system accessibility service enabled — getEnabledAccessibilityServiceList() returns empty.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "Third-party accessibility service is enabled — banking-trojan defense treats this as suspicious.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `accessibility_service_on` in profile.".to_string(),
        },
    });
    m.insert("app-defense-mediaprojection", |p: &DeviceProfile| match p.media_projection_active {
        Some(false) => SimulationVerdict::Bypassed {
            how: "No active MediaProjection session — screen is not being captured.".to_string(),
        },
        Some(true) => SimulationVerdict::Triggered {
            why: "MediaProjection session is active — app suspects screen recording / screenshot capture.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `media_projection_active` in profile.".to_string(),
        },
    });
    m.insert("app-defense-drm-attestation", |p: &DeviceProfile| match (p.widevine_l1, p.is_emulator) {
        (Some(true), _) => SimulationVerdict::Bypassed {
            how: "Widevine L1 attestation available — strong hardware-backed DRM identity verified.".to_string(),
        },
        (Some(false), Some(true)) => SimulationVerdict::Triggered {
            why: "Emulator reports Widevine L3 only — MediaDrm attestation is weak, app rejects.".to_string(),
        },
        (Some(false), Some(false)) => SimulationVerdict::Bypassed {
            how: "Widevine L3 on a real device is acceptable for most apps (only fails if app strictly requires L1).".to_string(),
        },
        _ => SimulationVerdict::Unknown {
            note: "Set `widevine_l1` (and optionally `is_emulator`) in profile.".to_string(),
        },
    });
    m.insert("app-defense-knox-tima", |p: &DeviceProfile| match p.is_samsung_knox {
        Some(true) => SimulationVerdict::Bypassed {
            how: "Samsung KNOX / TIMA attestation available — hardware-backed chain verified.".to_string(),
        },
        Some(false) => SimulationVerdict::Triggered {
            why: "Device is not Samsung — KNOX TIMA attestation API call will fail (or app falls back to weaker check).".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `is_samsung_knox` in profile.".to_string(),
        },
    });
    m.insert("app-defense-play-services-presence", |p: &DeviceProfile| match p.play_services_available {
        Some(true) => SimulationVerdict::Bypassed {
            how: "Google Play Services installed and up-to-date — isGooglePlayServicesAvailable() returns SUCCESS.".to_string(),
        },
        Some(false) => SimulationVerdict::Triggered {
            why: "Play Services missing or outdated — isGooglePlayServicesAvailable() returns SERVICE_MISSING / SERVICE_VERSION_UPDATE_REQUIRED.".to_string(),
        },
        None => SimulationVerdict::Unknown {
            note: "Set `play_services_available` in profile.".to_string(),
        },
    });

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Finding;
    use signatures::{BlockBehavior, Category, Severity};

    fn make_finding(id: &str, cat: Category, sev: Severity) -> Finding {
        Finding {
            rule_id: id.to_string(),
            rule_name: format!("Test {}", id),
            category: cat,
            severity: sev,
            behavior: BlockBehavior::HardBlock,
            evidence: "test".to_string(),
            bypass_hint_key: None,
        }
    }

    fn make_report(findings: Vec<Finding>) -> Report {
        let mut r = Report::new("/tmp/test.apk");
        r.findings = findings;
        r
    }

    /// A clean device should bypass EVERY root check we throw at it.
    #[test]
    fn test_clean_device_bypasses_root_checks() {
        let report = make_report(vec![
            make_finding("root-check-su-binary", Category::Root, Severity::Medium),
            make_finding("root-check-ro-secure-prop", Category::Root, Severity::Low),
            make_finding("root-magisk-binary", Category::Root, Severity::High),
        ]);
        let profile = DeviceProfile::preset("clean").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, bypassed, unknown) = sim.counts();
        assert_eq!(triggered, 0, "clean device must NOT trigger root checks");
        assert_eq!(bypassed, 3, "all 3 root findings should be Bypassed");
        assert_eq!(unknown, 0);
    }

    /// A rooted device with Magisk DenyList ON bypasses su + magisk checks
    /// but still triggers on test-keys (which DenyList doesn't fix).
    #[test]
    fn test_rooted_magisk_bypasses_denylist_protected_checks() {
        let report = make_report(vec![
            make_finding("root-check-su-binary", Category::Root, Severity::Medium),
            make_finding("root-magisk-binary", Category::Root, Severity::High),
            make_finding("root-test-keys-build", Category::Root, Severity::Low),
        ]);
        let profile = DeviceProfile::preset("rooted-magisk").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, bypassed, _unknown) = sim.counts();
        // su + magisk: bypassed (DenyList hides them)
        // test-keys: triggered (DenyList doesn't change ro.build.tags)
        assert_eq!(triggered, 1, "test-keys should still trigger");
        assert_eq!(bypassed, 2, "su + magisk bypassed by DenyList");
    }

    /// A rooted device WITHOUT DenyList triggers every root check.
    #[test]
    fn test_rooted_no_magisk_triggers_all_root_checks() {
        let report = make_report(vec![
            make_finding("root-check-su-binary", Category::Root, Severity::Medium),
            make_finding("root-magisk-binary", Category::Root, Severity::High),
            make_finding("root-test-keys-build", Category::Root, Severity::Low),
        ]);
        let profile = DeviceProfile::preset("rooted-no-magisk").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, _bypassed, _unknown) = sim.counts();
        assert_eq!(triggered, 3, "all root checks should trigger");
    }

    /// Emulator triggers Build.FINGERPRINT, files, network, telephony,
    /// sensors, BlueStacks checks — basically the entire anti-emulator
    /// suite.
    #[test]
    fn test_emulator_triggers_anti_emulator_checks() {
        let report = make_report(vec![
            make_finding(
                "anti-emulator-build-fingerprint",
                Category::AntiEmulator,
                Severity::Medium,
            ),
            make_finding(
                "anti-emulator-files",
                Category::AntiEmulator,
                Severity::High,
            ),
            make_finding(
                "anti-emulator-network",
                Category::AntiEmulator,
                Severity::Medium,
            ),
            make_finding(
                "anti-emulator-telephony",
                Category::AntiEmulator,
                Severity::Medium,
            ),
            make_finding(
                "anti-emulator-sensors",
                Category::AntiEmulator,
                Severity::Medium,
            ),
            make_finding(
                "anti-emulator-bluestacks",
                Category::AntiEmulator,
                Severity::High,
            ),
        ]);
        let profile = DeviceProfile::preset("emulator").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, _bypassed, _unknown) = sim.counts();
        assert_eq!(
            triggered, 6,
            "all 6 anti-emulator checks should trigger on emulator"
        );
    }

    /// Frida running triggers every anti-hook check.
    #[test]
    fn test_frida_triggers_anti_hook_checks() {
        let report = make_report(vec![
            make_finding(
                "anti-hook-frida-maps-scan",
                Category::AntiHooking,
                Severity::High,
            ),
            make_finding(
                "anti-hook-frida-default-port",
                Category::AntiHooking,
                Severity::Medium,
            ),
        ]);
        let profile = DeviceProfile::preset("frida").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, _bypassed, _unknown) = sim.counts();
        assert_eq!(triggered, 2, "both Frida checks should trigger");
    }

    /// An unknown rule_id (not in the verdict table) yields `Unknown`.
    #[test]
    fn test_unknown_rule_id_yields_unknown_verdict() {
        let report = make_report(vec![make_finding(
            "some-future-rule-not-yet-mapped",
            Category::Root,
            Severity::Medium,
        )]);
        let profile = DeviceProfile::preset("clean").unwrap();
        let sim = simulate(&report, &profile);
        let (triggered, bypassed, unknown) = sim.counts();
        assert_eq!(triggered, 0);
        assert_eq!(bypassed, 0);
        assert_eq!(unknown, 1, "unmapped rule must produce Unknown verdict");
    }

    /// A profile with None fields yields Unknown for any rule that needs them.
    #[test]
    fn test_unknown_profile_field_yields_unknown_verdict() {
        let report = make_report(vec![make_finding(
            "root-check-su-binary",
            Category::Root,
            Severity::Medium,
        )]);
        let profile = DeviceProfile::default(); // all fields None
        let sim = simulate(&report, &profile);
        let (triggered, bypassed, unknown) = sim.counts();
        assert_eq!(triggered, 0);
        assert_eq!(bypassed, 0);
        assert_eq!(unknown, 1, "missing profile fields must produce Unknown");
    }

    /// Profile JSON round-trips through to_json + from_json.
    #[test]
    fn test_profile_json_roundtrip() {
        let original = DeviceProfile::preset("rooted-magisk").unwrap();
        let json = original.to_json();
        let parsed = DeviceProfile::from_json(&json).expect("parse");
        assert_eq!(original, parsed);
    }

    /// from_json tolerates unknown keys (forward-compat with new profile fields).
    #[test]
    fn test_from_json_tolerates_unknown_keys() {
        let json = r#"{"rooted":true,"future_field":false}"#;
        let parsed = DeviceProfile::from_json(json).expect("parse");
        assert_eq!(parsed.rooted, Some(true));
    }

    /// from_json rejects malformed JSON.
    #[test]
    fn test_from_json_rejects_malformed() {
        assert!(DeviceProfile::from_json("not json").is_err());
        assert!(DeviceProfile::from_json("{rooted:true}").is_err()); // unquoted key
        assert!(DeviceProfile::from_json(r#"{"rooted":"yes"}"#).is_err()); // non-bool
    }

    /// Simulation report Markdown includes the summary table + per-verdict sections.
    #[test]
    fn test_simulation_markdown_has_summary_and_sections() {
        let report = make_report(vec![
            make_finding("root-check-su-binary", Category::Root, Severity::Medium),
            make_finding(
                "anti-hook-frida-maps-scan",
                Category::AntiHooking,
                Severity::High,
            ),
        ]);
        let profile = DeviceProfile::preset("rooted-no-magisk").unwrap();
        let sim = simulate(&report, &profile);
        let md = sim.to_markdown();

        assert!(md.contains("# APK Detector — Device Simulation Report"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("| Verdict | Count |"));
        assert!(md.contains("### 🔴 Triggered"));
        // root-check-su-binary on rooted-no-magisk is Triggered.
        assert!(md.contains("`root-check-su-binary`"));
        // anti-hook-frida on rooted-no-magisk (frida=false) is Bypassed.
        assert!(md.contains("### 🟢 Bypassed"));
        assert!(md.contains("`anti-hook-frida-maps-scan`"));
    }

    /// JSON output is parseable + contains the expected top-level keys.
    #[test]
    fn test_simulation_json_shape() {
        let report = make_report(vec![make_finding(
            "root-check-su-binary",
            Category::Root,
            Severity::Medium,
        )]);
        let profile = DeviceProfile::preset("clean").unwrap();
        let sim = simulate(&report, &profile);
        let json = sim.to_json();

        // Sanity: starts with {, ends with }, contains the expected keys.
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"apk_path\""));
        assert!(json.contains("\"profile\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"entries\""));
        assert!(json.contains("\"verdict\":\"bypassed\""));
    }

    /// AppDefense rules: anti-debug triggers when debugger_attached=true.
    #[test]
    fn test_app_defense_anti_debug_triggers() {
        let report = make_report(vec![
            make_finding(
                "app-defense-anti-debug",
                Category::AppDefense,
                Severity::High,
            ),
            make_finding("app-defense-vpn", Category::AppDefense, Severity::Medium),
        ]);
        let mut profile = DeviceProfile::preset("clean").unwrap();
        profile.debugger_attached = Some(true);
        profile.vpn_active = Some(true);
        let sim = simulate(&report, &profile);
        let (triggered, _bypassed, _unknown) = sim.counts();
        assert_eq!(triggered, 2, "both anti-debug + VPN should trigger");
    }

    /// Preset names that don't exist return None.
    #[test]
    fn test_unknown_preset_returns_none() {
        assert!(DeviceProfile::preset("nonexistent").is_none());
    }

    /// All 6 presets are recognized.
    #[test]
    fn test_all_six_presets_recognized() {
        for name in &[
            "clean",
            "rooted-magisk",
            "rooted-no-magisk",
            "emulator",
            "frida",
            "dev-options-on",
        ] {
            assert!(
                DeviceProfile::preset(name).is_some(),
                "preset `{}` not recognized",
                name
            );
        }
    }
}
