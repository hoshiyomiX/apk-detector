# APK Detector

> On-device, offline-first Android utility that analyzes a target APK and reports **which app-defense mechanisms are actively blocking the user** — root detection, Play Integrity, MTD/RASP, app hardening, anti-tamper, anti-hooking, anti-emulator, and clone/repackage checks.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%20API%2024+-green.svg)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Rust%20%2B%20Kotlin%20Compose-orange.svg)](#)

## Why

Modern banking, fintech, and DRM-protected apps refuse to run — or silently degrade — when they detect a rooted device, an unlocked bootloader, an emulator, a hooked process, or a repackaged signature. End users, QA engineers, and security researchers usually have **no way to know _which_ specific check is failing**. APK Detector closes that gap: pick an APK, get a Markdown report naming every mechanism the app ships, with bypass hints for QA reproduction.

## Features (v0.1 MVP)

- **8 detection categories** scanned statically against the target APK:
  1. Root detection (`su`, Magisk, BusyBox, root Beer-style checks)
  2. Play Integrity API calls
  3. MTD / RASP SDKs (Promon SHIELD, OneSpan, Arxan, Guardsquare, Verimatrix, etc.)
  4. App hardening (packers: Bangcle, Ijiami, Qihoo, Tencent Legu, Jiagu)
  5. Anti-tamper (signature/self-integrity checks)
  6. Anti-hooking (Frida, Xposed, Substrate, LSPlant detection)
  7. Anti-emulator (Build.FINGERPRINT, qemu, goldfish, generic checks)
  8. Clone / repackage detection (app-cloning SDKs, package-name hash checks)
- **Markdown report** for Dev/QA audience, with severity, evidence, and **bypass hints**
- **Diff mode** — compare two APK versions and surface newly added/removed detections
- **Batch scan** — queue multiple APKs
- **Share** report via Android share sheet
- **History** — local Room database of past scans

## Design principles

| Principle | How |
|---|---|
| On-device only | No `INTERNET` permission in the detector app itself |
| No code execution of target | Pure static analysis on bytes — we never run the target APK |
| Reproducible signatures | Detection rules are YAML, versioned in repo, not hardcoded |
| Polyglot core, thin UI | Rust engine + JNI bridge; Kotlin Compose is a shell |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Kotlin / Jetpack Compose UI (5 screens)                    │
│  Picker → ScanProgress → ReportView → DiffView → History    │
└────────────────────┬────────────────────────────────────────┘
                     │ JNI
┌────────────────────▼────────────────────────────────────────┐
│  jni-bridge  (4 functions: scan / diff / listSignatures / ver)│
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│  detector   (8 submodules + bypass_hints + report + diff)   │
└────────────────────┬────────────────────────────────────────┘
                     │
       ┌─────────────┴──────────────┐
       ▼                            ▼
┌─────────────┐              ┌──────────────┐
│  apk-parser │              │  signatures  │
│  (DEX, ELF, │              │  (8 YAML +   │
│   Manifest) │              │   loader)    │
└─────────────┘              └──────────────┘
```

**Crate layout (Rust workspace):**

```
rust/
├── Cargo.toml          # workspace
├── apk-parser/         # ZIP, AXML, DEX, ELF parsing
├── signatures/         # YAML detection rules + loader
├── detector/           # 8 detectors + bypass hints + report + diff
│   └── src/
│       ├── root.rs
│       ├── play_integrity.rs
│       ├── mtd_rasp.rs
│       ├── app_hardening.rs
│       ├── anti_tamper.rs
│       ├── anti_hooking.rs
│       ├── anti_emulator.rs
│       ├── clone_repackage.rs
│       ├── bypass_hints.rs
│       ├── report.rs
│       └── diff.rs
└── jni-bridge/         # 4 JNI exports consumed by Kotlin
```

**Android module layout:**

```
android/
├── app/
│   ├── src/main/
│   │   ├── java/id/zai/apkdetector/
│   │   │   ├── MainActivity.kt
│   │   │   ├── ui/         # 5 Compose screens
│   │   │   ├── data/       # NativeBridge, Repository, HistoryDB
│   │   │   └── markdown/   # MarkdownRenderer
│   │   ├── AndroidManifest.xml
│   │   └── jniLibs/        # libapk_detector.so per ABI
│   └── build.gradle.kts
├── build.gradle.kts
└── settings.gradle.kts
```

## Build

### Native (Rust)

```bash
# Install target toolchains
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Build all ABIs into android/app/src/main/jniLibs/
cd rust
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../android/app/src/main/jniLibs build --release
```

### Android

```bash
cd android
./gradlew :app:assembleRelease
# → app/build/outputs/apk/release/app-release.apk
```

> Requires Android SDK 34, NDK r26+, JDK 17.

## Development status

| Area | Status |
|---|---|
| Repo scaffold + LICENSE + CI skeleton | ✅ v0.1.0 |
| `apk-parser` crate (ZIP, AXML, DEX reader) | 🚧 next |
| `signatures` crate (8 YAML) | 🚧 next |
| `detector` crate (8 modules + report + diff + bypass) | 🚧 next |
| `jni-bridge` (4 functions) | 🚧 next |
| Kotlin Compose UI (5 screens) | 🚧 next |
| Room history DB + Share | 🚧 next |
| Dynamic runtime analysis (frida-trace style) | 🔜 v0.2 |
| Network analysis (certificate pinning, MITM detection) | 🔵 v0.3 |

## Detection signatures

All detection rules live under `rust/signatures/yaml/*.yaml` and follow a stable schema (`id`, `category`, `severity`, `evidence`, `bypass`). External researchers can PR new signatures without touching Rust code.

## Security & responsible use

- APK Detector performs **static analysis only**. It does not modify, patch, or run the target APK.
- Bypass hints are intended for **QA / authorized security research**. Don't use them to circumvent protections on apps you don't own or have written authorization to test.
- The detector app itself ships with **no `INTERNET` permission** — reports never leave the device unless the user explicitly shares them.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Public, MIT-licensed, PRs welcome. Please:
- Add new detections as YAML in `rust/signatures/yaml/`
- Include a test APK hash (or class name evidence) in the PR description
- Don't commit secrets, API tokens, or proprietary APK samples
