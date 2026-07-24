//! Aggregated scan report and Markdown renderer.

use std::collections::HashMap;
use std::fmt::Write as _;

use signatures::{Category, DetectionRule, Severity, SignatureSet};

/// One detected rule firing against the target APK.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: Category,
    pub severity: Severity,
    /// Human-readable evidence (e.g. the matched string + location).
    pub evidence: String,
    pub bypass_hint_key: Option<String>,
}

/// What happened during the scan (success / soft-failure reasons).
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    /// Scan completed normally.
    Ok,
    /// APK was parseable but one or more sub-parsers skipped chunks (e.g.
    /// multidex beyond the first 10 DEX files). Findings are still valid.
    Partial(String),
    /// APK could not be opened at all.
    Failed(String),
}

/// Final scan result.
#[derive(Debug, Clone)]
pub struct Report {
    pub apk_path: String,
    pub apk_package: Option<String>,
    pub apk_size_bytes: u64,
    pub apk_sha256: Option<String>,
    pub outcome: ScanOutcome,
    pub findings: Vec<Finding>,
    pub signature_count: usize,
    pub engine_version: &'static str,
}

impl Report {
    pub fn new(apk_path: impl Into<String>) -> Self {
        Self {
            apk_path: apk_path.into(),
            apk_package: None,
            apk_size_bytes: 0,
            apk_sha256: None,
            outcome: ScanOutcome::Ok,
            findings: Vec::new(),
            signature_count: 0,
            engine_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Group findings by category, returning categories in canonical order.
    pub fn by_category(&self) -> Vec<(Category, Vec<&Finding>)> {
        let mut by_cat: HashMap<Category, Vec<&Finding>> = HashMap::new();
        for f in &self.findings {
            by_cat.entry(f.category).or_default().push(f);
        }
        let mut out = Vec::with_capacity(8);
        for c in signatures::ALL_CATEGORIES {
            if let Some(v) = by_cat.remove(c) {
                out.push((*c, v));
            }
        }
        out
    }

    /// Render as Markdown. Audience: Dev/QA.
    pub fn to_markdown(&self, sigs: &SignatureSet) -> String {
        let mut md = String::with_capacity(8 * 1024);
        let _ = writeln!(md, "# APK Detector Report");
        let _ = writeln!(md);
        let _ = writeln!(md, "**Engine:** APK Detector v{}", self.engine_version);
        let _ = writeln!(md, "**Target:** `{}`", self.apk_path);
        if let Some(pkg) = &self.apk_package {
            let _ = writeln!(md, "**Package:** `{}`", pkg);
        }
        if let Some(sha) = &self.apk_sha256 {
            let _ = writeln!(md, "**SHA-256:** `{}`", sha);
        }
        let _ = writeln!(md, "**Size:** {} bytes", self.apk_size_bytes);
        let _ = writeln!(md, "**Rules loaded:** {}", self.signature_count);
        let _ = writeln!(md, "**Findings:** {}", self.findings.len());
        let _ = writeln!(md);

        // Summary table
        let _ = writeln!(md, "## Summary by Category");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Category | Findings | Highest severity |");
        let _ = writeln!(md, "|---|---:|---|");
        for (cat, finds) in self.by_category() {
            let count = finds.len();
            let highest = finds
                .iter()
                .map(|f| f.severity)
                .max_by_key(|s| severity_rank(*s))
                .map(|s| s.as_str())
                .unwrap_or("—");
            let _ = writeln!(md, "| {} | {} | {} |", category_label(cat), count, highest);
        }
        let _ = writeln!(md);

        // Per-category detail
        let _ = writeln!(md, "## Detailed Findings");
        let _ = writeln!(md);
        if self.findings.is_empty() {
            let _ = writeln!(md, "_No detections. The APK does not appear to ship any of the defense mechanisms tracked by APK Detector v0.1._");
            let _ = writeln!(md);
        } else {
            for (cat, finds) in self.by_category() {
                let _ = writeln!(
                    md,
                    "### {} ({} finding{})",
                    category_label(cat),
                    finds.len(),
                    if finds.len() == 1 { "" } else { "s" }
                );
                let _ = writeln!(md);
                // Sort findings within category by severity desc, then by rule id
                let mut sorted: Vec<&Finding> = finds.clone();
                sorted.sort_by(|a, b| {
                    severity_rank(b.severity)
                        .cmp(&severity_rank(a.severity))
                        .then_with(|| a.rule_id.cmp(&b.rule_id))
                });
                for f in sorted {
                    let _ = writeln!(
                        md,
                        "**{} {}** `{}`",
                        f.severity.emoji(),
                        f.severity.as_str().to_uppercase(),
                        f.rule_id
                    );
                    let _ = writeln!(md, ": {}", f.rule_name);
                    let _ = writeln!(md);
                    let _ = writeln!(md, "- Evidence: `{}`", truncate_for_md(&f.evidence, 200));
                    if let Some(key) = &f.bypass_hint_key {
                        if let Some(hint) = crate::bypass_hints::lookup(key) {
                            let _ = writeln!(md, "- **Bypass hint:** {}", hint);
                        }
                    }
                    if let Some(rule) = sigs.by_id(&f.rule_id) {
                        let _ = writeln!(md, "- Description: {}", rule.description);
                    }
                    let _ = writeln!(md);
                }
            }
        }

        // Outcome footer
        match &self.outcome {
            ScanOutcome::Ok => {}
            ScanOutcome::Partial(reason) => {
                let _ = writeln!(md, "## ⚠️ Partial Scan");
                let _ = writeln!(md);
                let _ = writeln!(md, "{}", reason);
                let _ = writeln!(md);
            }
            ScanOutcome::Failed(reason) => {
                let _ = writeln!(md, "## ❌ Scan Failed");
                let _ = writeln!(md);
                let _ = writeln!(md, "{}", reason);
                let _ = writeln!(md);
            }
        }

        md
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn category_label(c: Category) -> &'static str {
    match c {
        Category::Root => "Root Detection",
        Category::PlayIntegrity => "Play Integrity",
        Category::MtdRasp => "MTD / RASP",
        Category::AppHardening => "App Hardening",
        Category::AntiTamper => "Anti-Tamper",
        Category::AntiHooking => "Anti-Hooking",
        Category::AntiEmulator => "Anti-Emulator",
        Category::CloneRepackage => "Clone / Repackage",
    }
}

fn truncate_for_md(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{}…", truncated)
    }
}

/// Convert a `DetectionRule` match into a `Finding` for the report.
pub(crate) fn finding_from_rule(rule: &DetectionRule, evidence: impl Into<String>) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        category: rule.category,
        severity: rule.severity,
        evidence: evidence.into(),
        bypass_hint_key: rule.bypass_hint.clone(),
    }
}
