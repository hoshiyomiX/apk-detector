//! Diff engine — compares two scan reports and surfaces newly added/removed
//! detections. Used by the Diff screen to answer "what changed between
//! version A and version B of this APK?"

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use signatures::Category;

use crate::Finding;

/// Side-by-side diff of two reports' findings, keyed by `(rule_id, category)`.
#[derive(Debug, Clone)]
pub struct ReportDiff {
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
    pub unchanged: Vec<Finding>,
}

impl ReportDiff {
    pub fn from_findings(old: &[Finding], new: &[Finding]) -> Self {
        let old_keys: BTreeSet<String> = old
            .iter()
            .map(|f| format!("{}|{:?}", f.rule_id, f.category))
            .collect();
        let new_keys: BTreeSet<String> = new
            .iter()
            .map(|f| format!("{}|{:?}", f.rule_id, f.category))
            .collect();

        let added_keys: BTreeSet<&String> =
            new_keys.iter().filter(|k| !old_keys.contains(*k)).collect();
        let removed_keys: BTreeSet<&String> =
            old_keys.iter().filter(|k| !new_keys.contains(*k)).collect();
        let unchanged_keys: BTreeSet<&String> = old_keys.intersection(&new_keys).collect();

        let mut by_key_new: BTreeMap<String, Finding> = BTreeMap::new();
        for f in new {
            by_key_new.insert(format!("{}|{:?}", f.rule_id, f.category), f.clone());
        }
        let mut by_key_old: BTreeMap<String, Finding> = BTreeMap::new();
        for f in old {
            by_key_old.insert(format!("{}|{:?}", f.rule_id, f.category), f.clone());
        }

        let added = added_keys
            .iter()
            .filter_map(|k| by_key_new.get(*k).cloned())
            .collect();
        let removed = removed_keys
            .iter()
            .filter_map(|k| by_key_old.get(*k).cloned())
            .collect();
        let unchanged = unchanged_keys
            .iter()
            .filter_map(|k| by_key_new.get(*k).cloned())
            .collect();

        Self {
            added,
            removed,
            unchanged,
        }
    }

    pub fn to_markdown(&self, old_label: &str, new_label: &str) -> String {
        let mut md = String::with_capacity(4 * 1024);
        let _ = writeln!(md, "# APK Detector — Diff Report");
        let _ = writeln!(md);
        let _ = writeln!(md, "Comparing **{}** → **{}**", old_label, new_label);
        let _ = writeln!(md);
        let _ = writeln!(md, "| Status | Count |");
        let _ = writeln!(md, "|---|---:|");
        let _ = writeln!(md, "| ➕ Added | {} |", self.added.len());
        let _ = writeln!(md, "| ➖ Removed | {} |", self.removed.len());
        let _ = writeln!(md, "| = Unchanged | {} |", self.unchanged.len());
        let _ = writeln!(md);

        if !self.added.is_empty() {
            let _ = writeln!(md, "## ➕ Newly Added Detections");
            let _ = writeln!(md);
            render_finding_list(&mut md, &self.added);
        }
        if !self.removed.is_empty() {
            let _ = writeln!(md, "## ➖ Removed Detections");
            let _ = writeln!(md);
            render_finding_list(&mut md, &self.removed);
        }
        if !self.unchanged.is_empty() {
            let _ = writeln!(md, "## = Unchanged Detections");
            let _ = writeln!(md);
            let _ = writeln!(
                md,
                "<details><summary>{} unchanged finding(s) — click to expand</summary>",
                self.unchanged.len()
            );
            let _ = writeln!(md);
            render_finding_list(&mut md, &self.unchanged);
            let _ = writeln!(md, "</details>");
            let _ = writeln!(md);
        }
        md
    }
}

fn render_finding_list(md: &mut String, findings: &[Finding]) {
    // Group by category for readability
    let mut by_cat: BTreeMap<Category, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_cat.entry(f.category).or_default().push(f);
    }
    for (cat, list) in by_cat {
        let _ = writeln!(md, "### {:?}", cat);
        let _ = writeln!(md);
        for f in list {
            let _ = writeln!(
                md,
                "- **{}** `{}` — {} _(evidence: `{}`)",
                f.severity.emoji(),
                f.rule_id,
                f.rule_name,
                f.evidence
            );
        }
        let _ = writeln!(md);
    }
}
