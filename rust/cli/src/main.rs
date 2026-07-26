//! # apk-detector-cli
//!
//! Host-side CLI for the APK Detector engine. Lets you dissect an APK or
//! `.apks` bundle from any Linux/macOS/Windows shell — no Android device,
//! no NDK, no Kotlin app required.
//!
//! Built so the same Rust engine that runs on-device via `jni-bridge` can
//! be exercised against a target APK during CI, security research, or
//! pre-release QA.
//!
//! ## Usage
//!
//! ```text
//! apk-detector-cli <APK_OR_APKS_PATH> [OPTIONS]
//! ```
//!
//! ## Options
//!
//! - `--blocking-only` — show only Medium/High/Critical findings (block/restrict filter)
//! - `--simulate-preset <NAME>` — simulate against a curated preset profile
//!   (`clean`, `rooted-magisk`, `rooted-no-magisk`, `emulator`, `frida`, `dev-options-on`)
//! - `--simulate-profile <JSON>` — simulate against a custom profile JSON
//!   (e.g. `'{"rooted":true,"magisk_denylist_on":true}'`)
//! - `--out <FILE>` — write Markdown to FILE instead of stdout
//! - `--json` — output simulation result as JSON (only valid with --simulate-*)
//!
//! ## Exit codes
//!
//! - 0 — scan succeeded, report rendered
//! - 1 — argument error, file not found, parse error, or internal panic
//!
//! ## PANIC SAFETY
//!
//! The CLI wraps the entire scan body in `std::panic::catch_unwind`. A
//! caught panic is printed to stderr as `internal panic: <msg>` and the
//! process exits 1 — no SIGABRT, no core dump. This mirrors the JNI
//! bridge's panic safety contract.

use std::fs::File;
use std::io::Write;
use std::process::ExitCode;

use detector::full_scan;
use detector::{simulate, DeviceProfile};
use signatures::SignatureSet;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!();
            eprintln!("Usage: apk-detector-cli <APK_OR_APKS_PATH> [OPTIONS]");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  --blocking-only              Show only Medium/High/Critical findings");
            eprintln!("  --simulate-preset <NAME>     Simulate against a curated preset");
            eprintln!("                               (clean|rooted-magisk|rooted-no-magisk|emulator|frida|dev-options-on)");
            eprintln!("  --simulate-profile <JSON>    Simulate against a custom profile JSON");
            eprintln!("                               (e.g. '{{\"rooted\":true,\"magisk_denylist_on\":true}}')");
            eprintln!(
                "  --out <FILE>                 Write Markdown/JSON to FILE instead of stdout"
            );
            eprintln!("  --json                       Output JSON (only valid with --simulate-*)");
            return ExitCode::from(1);
        }
    };

    // Load embedded signature set (compiled into the binary)
    let sigs = match SignatureSet::load_embedded() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to load embedded signatures: {}", e);
            return ExitCode::from(1);
        }
    };

    // Open the APK / .apks file. `open_any` dispatches by extension:
    // .apk → streaming File read, .apks → BundleTool ZIP-of-APKs (extracts
    // base.apk into memory).
    let path = &parsed.apk_path;
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: open {}: {}", path, e);
            return ExitCode::from(1);
        }
    };
    let reader: apk_parser::AnyReader = Box::new(file);
    let mut apk = match apk_parser::open_any(reader, path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: apk parse {}: {}", path, e);
            return ExitCode::from(1);
        }
    };

    // Run the full scan inside a panic boundary. A malformed APK could
    // trigger a panic deep in the parser or detector — we catch it here
    // so the CLI process exits cleanly with a diagnostic, rather than
    // aborting with SIGABRT.
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        full_scan(path, &mut apk, &sigs)
    }));
    let report = match scan_result {
        Ok(r) => r,
        Err(payload) => {
            let msg = panic_payload_to_string(payload);
            eprintln!("Error: internal panic: {}", msg);
            return ExitCode::from(1);
        }
    };

    // Resolve the output mode: full, blocking-only, or simulate-*.
    // If both --simulate-preset and --simulate-profile are given, preset wins
    // (we log to stderr so the user knows).
    let simulate_profile: Option<DeviceProfile> = if let Some(name) = &parsed.simulate_preset {
        match DeviceProfile::preset(name) {
            Some(p) => Some(p),
            None => {
                eprintln!(
                    "Error: unknown --simulate-preset `{}`. Valid presets: clean, rooted-magisk, rooted-no-magisk, emulator, frida, dev-options-on",
                    name
                );
                return ExitCode::from(1);
            }
        }
    } else if let Some(json) = &parsed.simulate_profile {
        match DeviceProfile::from_json(json) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("Error: --simulate-profile parse: {}", e);
                return ExitCode::from(1);
            }
        }
    } else {
        None
    };

    // Render Markdown / JSON
    let (output, ext_label): (String, &'static str) = if let Some(profile) = simulate_profile {
        let sim = simulate(&report, &profile);
        if parsed.json {
            (sim.to_json(), "json")
        } else {
            (sim.to_markdown(), "md")
        }
    } else if parsed.blocking_only {
        (report.to_markdown_blocking_only(&sigs), "md")
    } else {
        (report.to_markdown(&sigs), "md")
    };

    // Output to file or stdout
    if let Some(out_path) = &parsed.out_path {
        if let Err(e) = write_file(out_path, &output) {
            eprintln!("Error: write {}: {}", out_path, e);
            return ExitCode::from(1);
        }
        eprintln!(
            "Wrote {} bytes to {} ({} findings, {} blocking) [{}]",
            output.len(),
            out_path,
            report.findings.len(),
            report
                .findings
                .iter()
                .filter(|f| f.behavior.is_user_blocking())
                .count(),
            ext_label,
        );
    } else {
        print!("{}", output);
    }

    ExitCode::from(0)
}

/// Parsed CLI arguments.
struct ParsedArgs {
    apk_path: String,
    blocking_only: bool,
    out_path: Option<String>,
    simulate_preset: Option<String>,
    simulate_profile: Option<String>,
    json: bool,
}

/// Hand-rolled argument parser — no `clap` dependency. The CLI has only
/// 6 flags so this is simpler than pulling in a parser framework.
fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    if args.len() < 2 {
        return Err("Error: missing APK path argument".to_string());
    }
    let mut apk_path: Option<String> = None;
    let mut blocking_only = false;
    let mut out_path: Option<String> = None;
    let mut simulate_preset: Option<String> = None;
    let mut simulate_profile: Option<String> = None;
    let mut json = false;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--blocking-only" => {
                blocking_only = true;
            }
            "--simulate-preset" => {
                if i + 1 >= args.len() {
                    return Err("Error: --simulate-preset requires a name argument".to_string());
                }
                simulate_preset = Some(args[i + 1].clone());
                i += 1;
            }
            "--simulate-profile" => {
                if i + 1 >= args.len() {
                    return Err("Error: --simulate-profile requires a JSON argument".to_string());
                }
                simulate_profile = Some(args[i + 1].clone());
                i += 1;
            }
            "--out" => {
                if i + 1 >= args.len() {
                    return Err("Error: --out requires a file path argument".to_string());
                }
                out_path = Some(args[i + 1].clone());
                i += 1;
            }
            "--json" => {
                json = true;
            }
            "-h" | "--help" => {
                return Err("Help:".to_string()); // triggers usage print
            }
            s if s.starts_with("--") => {
                return Err(format!("Error: unknown flag: {}", s));
            }
            _ => {
                if apk_path.is_none() {
                    apk_path = Some(a.to_string());
                } else {
                    return Err(format!("Error: unexpected positional argument: {}", a));
                }
            }
        }
        i += 1;
    }
    let apk_path = apk_path.ok_or_else(|| "Error: missing APK path argument".to_string())?;

    // Validate: --json only makes sense with --simulate-*
    if json && simulate_preset.is_none() && simulate_profile.is_none() {
        return Err(
            "Error: --json is only valid with --simulate-preset or --simulate-profile".to_string(),
        );
    }

    Ok(ParsedArgs {
        apk_path,
        blocking_only,
        out_path,
        simulate_preset,
        simulate_profile,
        json,
    })
}

fn write_file(path: &str, content: &str) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Downcast a panic payload to a readable string. Mirrors the JNI bridge's
/// `panic_payload_to_string` — same three common payload types.
fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}
