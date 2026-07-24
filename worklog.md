---
last_phase: DELIVER
task: Implement APK Detector v0.1 MVP — Rust core + Kotlin Compose UI (IMPL-002 through IMPL-010)
complexity: Complex
task_type: Coding
files_modified:
  - rust/Cargo.toml (workspace root)
  - rust/apk-parser/* (6 .rs files + Cargo.toml)
  - rust/signatures/* (3 .rs files + 8 YAML + Cargo.toml)
  - rust/detector/* (12 .rs files + Cargo.toml)
  - rust/jni-bridge/* (2 .rs files + Cargo.toml)
  - android/* (3 gradle files + libs.versions.toml + proguard + gradle-wrapper props)
  - android/app/src/main/AndroidManifest.xml
  - android/app/src/main/res/* (5 XML resource files: strings, themes, colors, backup, data_extraction, launcher icons)
  - android/app/src/main/java/id/zai/apkdetector/* (13 Kotlin files: app, activity, data layer, UI screens, theme, markdown)
phase_trace: IDLE→SPECIFY→PLAN→IMPLEMENT→VERIFY→DELIVER
traceability: IMPL-001 (done prior) + IMPL-002 through IMPL-010 (this session) + IMPL-011 (done prior)
  - IMPL-002: Rust workspace Cargo.toml + 4 crate stubs — ✓
  - IMPL-003: apk-parser crate (ZIP central directory reader + AXML decoder + DEX string table + ELF arch sniff) — ✓
  - IMPL-004: signatures crate (8 YAML rule files + struct types + embedded loader with dedup tests) — ✓ 2 tests pass
  - IMPL-005: detector crate (8 modules + common scan plumbing + bypass_hints catalog + Markdown report + diff engine) — ✓
  - IMPL-006: jni-bridge crate (4 JNI exports + JNI_OnLoad; hand-rolled FFI, no jni-sys dep) — ✓ all 5 symbols exported in libjni_bridge.so (555K)
  - IMPL-007: Android Gradle project (settings + root + app build.gradle.kts + libs.versions.toml + gradle wrapper props) — ✓
  - IMPL-008: Kotlin Compose UI (5 screens: Picker, ScanProgress, Report, Diff, History) + AppNavGraph + Theme — ✓
  - IMPL-009: Kotlin data layer (NativeBridge JNI bindings + Repository w/ SAF-URI-to-cache-path bridging + Room HistoryDatabase + custom MarkdownRenderer) — ✓
  - IMPL-010: AndroidManifest.xml — no INTERNET permission, SAF picker intent-filter, share-apk intent-filter — ✓
  - IMPL-011: GitHub Actions CI workflow — ✓ (done in prior session)
pivot: NONE
scope_drift: NONE
next_step: User to run `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/app/src/main/jniLibs build --release` on a machine with NDK r26+ installed, then `./gradlew :app:assembleDebug` to produce the installable APK. CI will do this on push automatically. After that: install APK on device, pick OCTO Mobile Banking APK, verify Markdown report renders the 8 detection categories.
