//! YAML signature loader. Reads all `.yaml` files under `yaml/` at compile time
//! (via `include_str!`) and parses them into a `SignatureSet`.
//!
//! Embedding rules at compile time keeps the binary self-contained — no
//! filesystem reads needed on-device. New rules ship with a new build.

use std::collections::HashMap;

use thiserror::Error;

use crate::types::{Category, DetectionRule};

#[derive(Debug, Error)]
pub enum SignatureSetError {
    #[error("YAML parse error in {file}: {source}")]
    Yaml {
        file: &'static str,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("empty signature set — no YAML rules found")]
    Empty,
}

/// All built-in detection rules, indexed by category and by id.
pub struct SignatureSet {
    rules: Vec<DetectionRule>,
    by_category: HashMap<Category, Vec<usize>>,
    by_id: HashMap<String, usize>,
}

impl SignatureSet {
    /// Load the embedded rule set. The macro `inline_rules!()` (below) generates
    /// the `(file_name, include_str!(...))` tuples for every YAML file in `yaml/`.
    pub fn load_embedded() -> Result<Self, SignatureSetError> {
        let entries: &[(&'static str, &'static str)] = inline_rules!();
        let mut rules = Vec::new();
        for (file, content) in entries {
            let parsed: Vec<DetectionRule> = serde_yaml::from_str(content)
                .map_err(|e| SignatureSetError::Yaml { file, source: e })?;
            rules.extend(parsed);
        }
        if rules.is_empty() {
            return Err(SignatureSetError::Empty);
        }
        Ok(Self::from_rules(rules))
    }

    /// Construct from an externally-supplied rule list (used by tests).
    pub fn from_rules(rules: Vec<DetectionRule>) -> Self {
        let mut by_category: HashMap<Category, Vec<usize>> = HashMap::new();
        let mut by_id: HashMap<String, usize> = HashMap::new();
        for (i, r) in rules.iter().enumerate() {
            by_category.entry(r.category).or_default().push(i);
            by_id.insert(r.id.clone(), i);
        }
        Self {
            rules,
            by_category,
            by_id,
        }
    }

    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }
    pub fn by_category(&self, c: Category) -> &[usize] {
        self.by_category
            .get(&c)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
    pub fn by_id(&self, id: &str) -> Option<&DetectionRule> {
        self.by_id.get(id).map(|&i| &self.rules[i])
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Macro: expands to a slice of `("filename.yaml", include_str!("yaml/filename.yaml"))`
/// tuples for every shipped rule file. Add a new rule file → add a line here.
macro_rules! inline_rules {
    () => {
        &[
            ("root.yaml", include_str!("../yaml/root.yaml")),
            (
                "play_integrity.yaml",
                include_str!("../yaml/play_integrity.yaml"),
            ),
            ("mtd_rasp.yaml", include_str!("../yaml/mtd_rasp.yaml")),
            (
                "app_hardening.yaml",
                include_str!("../yaml/app_hardening.yaml"),
            ),
            ("anti_tamper.yaml", include_str!("../yaml/anti_tamper.yaml")),
            (
                "anti_hooking.yaml",
                include_str!("../yaml/anti_hooking.yaml"),
            ),
            (
                "anti_emulator.yaml",
                include_str!("../yaml/anti_emulator.yaml"),
            ),
            (
                "clone_repackage.yaml",
                include_str!("../yaml/clone_repackage.yaml"),
            ),
            ("app_defense.yaml", include_str!("../yaml/app_defense.yaml")),
        ]
    };
}
pub(crate) use inline_rules;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_have_rules() {
        let s = SignatureSet::load_embedded().expect("embedded rules load");
        for cat in crate::ALL_CATEGORIES {
            assert!(
                !s.by_category(*cat).is_empty(),
                "category {:?} has zero rules",
                cat
            );
        }
    }

    #[test]
    fn rule_ids_unique() {
        let s = SignatureSet::load_embedded().expect("embedded rules load");
        let mut ids: Vec<&str> = s.rules.iter().map(|r| r.id.as_str()).collect();
        ids.sort();
        let initial = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), initial, "duplicate rule ids detected");
    }
}
