//! Aggregated scan report and Markdown renderer.

use std::collections::HashMap;
use std::fmt::Write as _;

use signatures::{BlockBehavior, Category, DetectionRule, Severity, SignatureSet};

/// One detected rule firing against the target APK.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: Category,
    pub severity: Severity,
    /// Runtime behavior — what the app actually DOES when this rule fires.
    /// Populated from the rule's `behavior` field. Used by
    /// `to_markdown_blocking_only` to filter the report down to findings
    /// that ACTUALLY restrict user access (process_kill / hard_block /
    /// soft_block). Findings with `LogOnly` or `Unknown` behavior are
    /// hidden by the blocking-only filter — they don't block the user.
    pub behavior: BlockBehavior,
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

    /// Render a **filtered** Markdown report containing only findings whose
    /// `behavior.is_user_blocking()` (i.e., `process_kill` / `hard_block` /
    /// `soft_block` — the runtime behaviors that ACTUALLY restrict user
    /// access by forcing the app to stop, blocking the user from proceeding,
    /// or closing access to features).
    ///
    /// Findings with `log_only` or `unknown` behavior are dropped — they
    /// represent detections that record telemetry but don't impact the user.
    /// This is the SEMANTIC filter the user requested: "Sorting deteksi mana
    /// saja yang memaksa aplikasi berhenti, stop, dan menutup akses bagi
    /// user yang terdeteksi. Abaikan deteksi lain jika itu tidak bersifat
    /// membatasi akses user terdeteksi."
    ///
    /// This is a stricter and more accurate filter than the previous
    /// severity-based filter (Medium/High/Critical) because:
    /// - Some Medium rules just log telemetry (e.g., `mtd-guardsquare-proguard-mapping`)
    /// - Some Low rules hard-block the user (e.g., `root-check-ro-secure-prop`)
    /// - Behavior is the GROUND TRUTH of what happens to the user.
    ///
    /// Same shape as `to_markdown` so the renderer on the UI side can drop
    /// in this method without changes.
    pub fn to_markdown_blocking_only(&self, sigs: &SignatureSet) -> String {
        let mut md = String::with_capacity(8 * 1024);
        let _ = writeln!(md, "# APK Detector Report — Block/Restrict Filter");
        let _ = writeln!(md);
        let _ = writeln!(
            md,
            "**Filter:** showing only findings whose runtime behavior would **force the app \
             to stop, block the user from proceeding, or close access to features** \
             (behavior: `process_kill` / `hard_block` / `soft_block`). Findings with \
             `log_only` or `unknown` behavior are hidden — they record telemetry but do \
             not impact the user. Use the full report to review them."
        );
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

        let blocking: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.behavior.is_user_blocking())
            .collect();
        let total = self.findings.len();
        let dropped = total - blocking.len();
        let _ = writeln!(
            md,
            "**Findings:** {} total ({} block/restrict, {} hidden by filter)",
            total,
            blocking.len(),
            dropped
        );
        let _ = writeln!(md);

        // Summary table — blocking only
        let _ = writeln!(md, "## Summary by Category (Block/Restrict Only)");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Category | Findings | Highest severity |");
        let _ = writeln!(md, "|---|---:|---|");
        // Build a per-category view of blocking findings only
        let mut by_cat_blocking: HashMap<Category, Vec<&Finding>> = HashMap::new();
        for f in &blocking {
            by_cat_blocking.entry(f.category).or_default().push(f);
        }
        for c in signatures::ALL_CATEGORIES {
            // Use `get` (not `remove`) so the map is still populated for the
            // detail section below. Double-drain bug: previously this was
            // `remove(c)` which emptied the map before the detail loop ran,
            // causing all per-category detail sections to silently disappear.
            if let Some(v) = by_cat_blocking.get(c) {
                let count = v.len();
                let highest = v
                    .iter()
                    .map(|f| f.severity)
                    .max_by_key(|s| severity_rank(*s))
                    .map(|s| s.as_str())
                    .unwrap_or("—");
                let _ = writeln!(md, "| {} | {} | {} |", category_label(*c), count, highest);
            }
        }
        let _ = writeln!(md);

        // Per-category detail
        let _ = writeln!(md, "## Detailed Findings (Block/Restrict Only)");
        let _ = writeln!(md);
        if blocking.is_empty() {
            let _ = writeln!(
                md,
                "_No blocking detections. The APK does not ship any defenses that would \
                 force the app to stop, block the user, or close access to features. \
                 Findings with `log_only` or `unknown` behavior (if any) are hidden by \
                 the filter — run a full scan to review them._"
            );
            let _ = writeln!(md);
        } else {
            // Group + order blocking findings by canonical category order
            let mut sorted_by_cat: Vec<(Category, Vec<&Finding>)> = Vec::with_capacity(8);
            for c in signatures::ALL_CATEGORIES {
                if let Some(v) = by_cat_blocking.remove(c) {
                    sorted_by_cat.push((*c, v));
                }
            }
            for (cat, finds) in sorted_by_cat {
                let _ = writeln!(
                    md,
                    "### {} ({} finding{})",
                    category_label(cat),
                    finds.len(),
                    if finds.len() == 1 { "" } else { "s" }
                );
                let _ = writeln!(md);
                let mut sorted: Vec<&Finding> = finds.clone();
                sorted.sort_by(|a, b| {
                    severity_rank(b.severity)
                        .cmp(&severity_rank(a.severity))
                        .then_with(|| a.rule_id.cmp(&b.rule_id))
                });
                for f in sorted {
                    let _ = writeln!(
                        md,
                        "**{} {}** `{}` _({})_",
                        f.severity.emoji(),
                        f.severity.as_str().to_uppercase(),
                        f.rule_id,
                        f.behavior.as_str(),
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

        // Outcome footer (same as full report)
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
        Category::AppDefense => "App Defense",
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
        behavior: rule.behavior,
        evidence: evidence.into(),
        bypass_hint_key: rule.bypass_hint.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signatures::SignatureSet;

    fn make_finding(id: &str, sev: Severity, cat: Category, behavior: BlockBehavior) -> Finding {
        Finding {
            rule_id: id.to_string(),
            rule_name: format!("Test finding {}", id),
            category: cat,
            severity: sev,
            behavior,
            evidence: "test evidence".to_string(),
            bypass_hint_key: None,
        }
    }

    fn make_report(findings: Vec<Finding>) -> Report {
        let mut r = Report::new("/tmp/test.apk");
        r.findings = findings;
        r.signature_count = 47;
        r
    }

    fn load_sigs() -> SignatureSet {
        SignatureSet::load_embedded().expect("embedded signatures load")
    }

    #[test]
    fn test_behavior_is_user_blocking_threshold() {
        // Sanity check the threshold directly on the BlockBehavior enum.
        // process_kill / hard_block / soft_block MUST be user-blocking.
        // log_only / unknown MUST NOT be user-blocking.
        assert!(
            BlockBehavior::ProcessKill.is_user_blocking(),
            "ProcessKill MUST be user-blocking"
        );
        assert!(
            BlockBehavior::HardBlock.is_user_blocking(),
            "HardBlock MUST be user-blocking"
        );
        assert!(
            BlockBehavior::SoftBlock.is_user_blocking(),
            "SoftBlock MUST be user-blocking"
        );
        assert!(
            !BlockBehavior::LogOnly.is_user_blocking(),
            "LogOnly must NOT be user-blocking"
        );
        assert!(
            !BlockBehavior::Unknown.is_user_blocking(),
            "Unknown must NOT be user-blocking (conservative)"
        );
    }

    #[test]
    fn test_blocking_filter_drops_log_only_and_unknown() {
        // Report with one of each behavior variant — filter should keep
        // process_kill / hard_block / soft_block, drop log_only / unknown.
        let findings = vec![
            make_finding(
                "log-1",
                Severity::Medium,
                Category::Root,
                BlockBehavior::LogOnly,
            ),
            make_finding(
                "unk-1",
                Severity::High,
                Category::Root,
                BlockBehavior::Unknown,
            ),
            make_finding(
                "soft-1",
                Severity::Medium,
                Category::Root,
                BlockBehavior::SoftBlock,
            ),
            make_finding(
                "hard-1",
                Severity::High,
                Category::AntiHooking,
                BlockBehavior::HardBlock,
            ),
            make_finding(
                "kill-1",
                Severity::Critical,
                Category::MtdRasp,
                BlockBehavior::ProcessKill,
            ),
        ];
        let report = make_report(findings);
        let sigs = load_sigs();
        let md = report.to_markdown_blocking_only(&sigs);

        // Header indicates filter applied
        assert!(
            md.contains("Block/Restrict Filter"),
            "filtered report header missing: {}",
            md.lines().take(3).collect::<Vec<_>>().join(" | ")
        );
        // LogOnly + Unknown findings MUST be hidden
        assert!(!md.contains("`log-1`"), "LogOnly leaked");
        assert!(!md.contains("`unk-1`"), "Unknown leaked");
        // SoftBlock + HardBlock + ProcessKill MUST be present
        assert!(
            md.contains("`soft-1`"),
            "SoftBlock finding missing from filter"
        );
        assert!(
            md.contains("`hard-1`"),
            "HardBlock finding missing from filter"
        );
        assert!(
            md.contains("`kill-1`"),
            "ProcessKill finding missing from filter"
        );
        // Counts in header: 5 total (3 blocking, 2 hidden)
        let findings_line = md
            .lines()
            .find(|l| l.starts_with("**Findings:**"))
            .unwrap_or("");
        assert!(
            findings_line.contains("5 total (3 block/restrict, 2 hidden by filter)"),
            "header counts wrong: {}",
            findings_line
        );
    }

    #[test]
    fn test_blocking_filter_with_all_log_only_unknown_renders_header() {
        // Edge case #1: report with only LogOnly/Unknown — filtered output
        // should still render the header + "no blocking detections" message,
        // not an empty string.
        let findings = vec![
            make_finding(
                "log-1",
                Severity::Medium,
                Category::Root,
                BlockBehavior::LogOnly,
            ),
            make_finding(
                "unk-1",
                Severity::High,
                Category::AntiEmulator,
                BlockBehavior::Unknown,
            ),
        ];
        let report = make_report(findings);
        let sigs = load_sigs();
        let md = report.to_markdown_blocking_only(&sigs);

        assert!(
            md.contains("Block/Restrict Filter"),
            "header missing on all-log-unknown report"
        );
        assert!(
            md.contains("No blocking detections"),
            "expected 'No blocking detections' message, got: {}",
            md
        );
        assert!(
            md.contains("2 hidden by filter"),
            "expected 2 hidden count in header"
        );
        // No findings leak
        assert!(!md.contains("`log-1`"));
        assert!(!md.contains("`unk-1`"));
    }

    #[test]
    fn test_blocking_filter_with_zero_findings_renders_header() {
        // Edge case #2: zero findings total. Filtered report must still
        // render the header (not an empty string).
        let report = make_report(vec![]);
        let sigs = load_sigs();
        let md = report.to_markdown_blocking_only(&sigs);

        assert!(
            md.contains("Block/Restrict Filter"),
            "header missing on empty report"
        );
        let findings_line = md
            .lines()
            .find(|l| l.starts_with("**Findings:**"))
            .unwrap_or("");
        assert!(
            findings_line.contains("0 total (0 block/restrict, 0 hidden by filter)"),
            "expected zero counts in header, got: {}",
            findings_line
        );
        assert!(md.contains("No blocking detections"));
    }

    #[test]
    fn test_blocking_filter_keeps_process_kill_only() {
        // Edge case #3: only ProcessKill findings — filter should keep all.
        let findings = vec![
            make_finding(
                "kill-1",
                Severity::Critical,
                Category::MtdRasp,
                BlockBehavior::ProcessKill,
            ),
            make_finding(
                "kill-2",
                Severity::Critical,
                Category::MtdRasp,
                BlockBehavior::ProcessKill,
            ),
        ];
        let report = make_report(findings);
        let sigs = load_sigs();
        let md = report.to_markdown_blocking_only(&sigs);

        assert!(md.contains("`kill-1`"));
        assert!(md.contains("`kill-2`"));
        let findings_line = md
            .lines()
            .find(|l| l.starts_with("**Findings:**"))
            .unwrap_or("");
        assert!(
            findings_line.contains("2 total (2 block/restrict, 0 hidden by filter)"),
            "expected 2/2/0 counts: {}",
            findings_line
        );
    }

    #[test]
    fn test_full_report_unaffected_by_filter_addition() {
        // Regression test: adding to_markdown_blocking_only must NOT change
        // the behavior of the original to_markdown method. A report with
        // mixed behaviors should still render ALL findings in full mode.
        let findings = vec![
            make_finding(
                "log-1",
                Severity::Medium,
                Category::Root,
                BlockBehavior::LogOnly,
            ),
            make_finding(
                "hard-1",
                Severity::High,
                Category::Root,
                BlockBehavior::HardBlock,
            ),
            make_finding(
                "kill-1",
                Severity::Critical,
                Category::MtdRasp,
                BlockBehavior::ProcessKill,
            ),
        ];
        let report = make_report(findings);
        let sigs = load_sigs();
        let full_md = report.to_markdown(&sigs);

        // Full report must include ALL findings, including LogOnly
        assert!(full_md.contains("`log-1`"), "LogOnly missing from full");
        assert!(full_md.contains("`hard-1`"));
        assert!(full_md.contains("`kill-1`"));
        // Full report must NOT have the "Block/Restrict Filter" header
        assert!(
            !full_md.contains("Block/Restrict Filter"),
            "full report accidentally shows filter header"
        );
    }

    #[test]
    fn test_yaml_rules_all_have_behavior_set() {
        // Every YAML rule should have a `behavior:` field set explicitly
        // (not relying on the `Unknown` default). This catches typos in
        // YAML migration and ensures the filter works correctly.
        let sigs = load_sigs();
        let mut unclassified: Vec<&str> = Vec::new();
        for rule in sigs.rules() {
            if rule.behavior == BlockBehavior::Unknown {
                unclassified.push(&rule.id);
            }
        }
        assert!(
            unclassified.is_empty(),
            "Found {} rules with `Unknown` behavior (missing `behavior:` field in YAML?): {}",
            unclassified.len(),
            unclassified.join(", ")
        );
    }
}
