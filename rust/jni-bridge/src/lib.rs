//! # jni-bridge
//!
//! JNI exports consumed by the Kotlin app `id.zai.apkdetector`.
//!
//! Four exports:
//!   - `Java_id_zai_apkdetector_NativeBridge_scanApk`     — scan a single APK
//!   - `Java_id_zai_apkdetector_NativeBridge_diffApks`    — diff two APKs
//!   - `Java_id_zai_apkdetector_NativeBridge_listSignatures` — list built-in rules
//!   - `Java_id_zai_apkdetector_NativeBridge_engineVersion`  — semver string
//!
//! All functions return Java strings (UTF-8). Errors are returned as a JSON
//! object `{"error": "..."}` so the Kotlin side can surface them in the UI.

// The actual implementation is in `api.rs`; this module just wires logging.
mod api;

use std::sync::OnceLock;

static LOG_INIT: OnceLock<()> = OnceLock::new();

fn ensure_logger() {
    LOG_INIT.get_or_init(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("apk_detector"),
        );
    });
}
