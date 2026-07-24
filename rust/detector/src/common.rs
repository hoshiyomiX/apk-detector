//! Shared detector plumbing used by all 8 detector modules.

use apk_parser::{Apk, ApkError};
use signatures::DetectionRule;

use crate::report::finding_from_rule;
use crate::Finding;

/// Run all `rules` whose `evidence_location` matches `DexString` against
/// every DEX file in the APK.
pub fn scan_dex_strings<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
    dex_cap: usize,
) {
    let dex_entries: Vec<String> = apk.dex_entries().iter().map(|e| e.name.clone()).collect();
    let dex_to_scan: Vec<String> = dex_entries.into_iter().take(dex_cap).collect();
    if dex_to_scan.is_empty() {
        return;
    }

    // Aggregate the union of all DEX string tables — saves pattern-scan time.
    let mut all_strings: Vec<String> = Vec::new();
    for dex_name in &dex_to_scan {
        match apk.read(dex_name) {
            Ok(bytes) => match apk_parser::DexStringTable::parse(&bytes) {
                Ok(tbl) => all_strings.extend(tbl.strings),
                Err(_) => continue,
            },
            Err(_) => continue,
        }
    }

    // Dedup strings for faster scanning
    all_strings.sort_unstable();
    all_strings.dedup();

    for rule in rules {
        for needle in &rule.patterns {
            // case-sensitive substring scan
            let hits: Vec<&String> = all_strings
                .iter()
                .filter(|s| s.contains(needle.as_str()))
                .collect();
            if !hits.is_empty() {
                let evidence = hits
                    .iter()
                    .take(3) // cap evidence at 3 hits per rule
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("`, `");
                findings.push(finding_from_rule(
                    rule,
                    format!("DEX string match: `{}`", evidence),
                ));
                break; // one finding per rule, even if multiple patterns match
            }
        }
    }
}

/// Run all `rules` whose `evidence_location` matches `Manifest` against the
/// decoded AndroidManifest.xml.
pub fn scan_manifest<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) -> Result<(), ApkError> {
    let bytes = apk.manifest()?;
    let xml = match apk_parser::BinaryXml::parse_slice(&bytes) {
        Ok(x) => x,
        Err(_) => return Ok(()),
    };
    // Concatenate all tag names + attr values into one big haystack
    let mut hay = String::new();
    for el in &xml.elements {
        hay.push_str(&el.tag);
        hay.push(' ');
        for (k, v) in &el.attrs {
            hay.push_str(k);
            hay.push('=');
            hay.push_str(v);
            hay.push(' ');
        }
    }

    for rule in rules {
        for needle in &rule.patterns {
            if hay.contains(needle.as_str()) {
                findings.push(finding_from_rule(
                    rule,
                    format!("Manifest match: `{}`", needle),
                ));
                break;
            }
        }
    }
    Ok(())
}

/// Run all `rules` whose `evidence_location` matches `NativeLibName` against
/// the names of native libs under `lib/<abi>/`.
pub fn scan_native_lib_names<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) -> Result<(), ApkError> {
    let libs = apk.native_libs()?;
    for rule in rules {
        for needle in &rule.patterns {
            let hit: Vec<&apk_parser::NativeLib> = libs
                .iter()
                .filter(|l| l.filename.contains(needle.as_str()))
                .collect();
            if !hit.is_empty() {
                let evidence = hit
                    .iter()
                    .take(3)
                    .map(|l| format!("lib/{}/{}", l.abi, l.filename))
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(finding_from_rule(rule, format!("Native lib: {}", evidence)));
                break;
            }
        }
    }
    Ok(())
}

/// Run all `rules` whose `evidence_location` matches `ZipEntry` against the
/// list of files in the APK ZIP.
pub fn scan_zip_entries<R: std::io::Read + std::io::Seek>(
    apk: &mut Apk<R>,
    rules: &[&DetectionRule],
    findings: &mut Vec<Finding>,
) {
    let names: Vec<&str> = apk.entries().iter().map(|e| e.name.as_str()).collect();
    for rule in rules {
        for needle in &rule.patterns {
            let hit: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| n.contains(needle.as_str()))
                .collect();
            if !hit.is_empty() {
                let evidence = hit.iter().take(3).copied().collect::<Vec<_>>().join(", ");
                findings.push(finding_from_rule(rule, format!("ZIP entry: {}", evidence)));
                break;
            }
        }
    }
}
