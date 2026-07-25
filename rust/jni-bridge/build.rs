//! Build script for jni-bridge.
//!
//! Captures the git commit SHA at build time and exposes it via the
//! `BUILD_SHA` environment variable, which `env!("BUILD_SHA")` reads in
//! api.rs::engineVersion(). This lets the user verify which build is
//! loaded on-device by reading the "Engine version" log line — e.g.
//! `0.1.0+e5114a4` vs `0.1.0+abc1234` — so we can distinguish a stale
//! cached .so from the new build.
//!
//! Falls back to "unknown" if git is unavailable or the repo has no
//! commits (e.g. a fresh tarball extract).

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=BUILD_SHA={}", sha);
    // Re-run if HEAD changes. We touch .git/HEAD which changes on every
    // checkout / commit.
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
