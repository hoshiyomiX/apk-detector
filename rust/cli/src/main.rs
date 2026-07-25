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
//! apk-detector-cli <APK_OR_APKS_PATH> [--blocking-only] [--out <FILE>]
//! ```
//!
//! - Default mode: produces the full Markdown report (all severities).
//! - `--blocking-only`: produces a filtered report containing only findings
//!   whose severity would block or restrict the user (Medium / High /
//!   Critical). Low and Info findings are hidden. Useful for answering
//!   "which defenses in this APK will actually stop a real user?"
//! - `--out <FILE>`: write the Markdown to a file instead of stdout.
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
use signatures::SignatureSet;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!();
            eprintln!(
                "Usage: apk-detector-cli <APK_OR_APKS_PATH> [--blocking-only] [--out <FILE>]"
            );
            eprintln!();
            eprintln!("Options:");
            eprintln!("  --blocking-only   Show only Medium/High/Critical findings (block/restrict filter)");
            eprintln!("  --out <FILE>      Write Markdown to FILE instead of stdout");
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

    // Render Markdown — full or filtered based on flag
    let md = if parsed.blocking_only {
        report.to_markdown_blocking_only(&sigs)
    } else {
        report.to_markdown(&sigs)
    };

    // Output to file or stdout
    if let Some(out_path) = &parsed.out_path {
        if let Err(e) = write_file(out_path, &md) {
            eprintln!("Error: write {}: {}", out_path, e);
            return ExitCode::from(1);
        }
        eprintln!(
            "Wrote {} bytes to {} ({} findings, {} blocking)",
            md.len(),
            out_path,
            report.findings.len(),
            report
                .findings
                .iter()
                .filter(|f| f.severity.is_blocking())
                .count()
        );
    } else {
        // stdout
        print!("{}", md);
    }

    ExitCode::from(0)
}

/// Parsed CLI arguments.
struct ParsedArgs {
    apk_path: String,
    blocking_only: bool,
    out_path: Option<String>,
}

/// Hand-rolled argument parser — no `clap` dependency. The CLI has only
/// 3 flags so this is simpler than pulling in a parser framework.
fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    if args.len() < 2 {
        return Err("Error: missing APK path argument".to_string());
    }
    let mut apk_path: Option<String> = None;
    let mut blocking_only = false;
    let mut out_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--blocking-only" => {
                blocking_only = true;
            }
            "--out" => {
                if i + 1 >= args.len() {
                    return Err("Error: --out requires a file path argument".to_string());
                }
                out_path = Some(args[i + 1].clone());
                i += 1;
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
    Ok(ParsedArgs {
        apk_path,
        blocking_only,
        out_path,
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
