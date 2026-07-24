//! Bypass hint catalog. Each `bypass_hint` key referenced by a rule resolves
//! to a one-paragraph guidance string aimed at QA / authorized security research.
//!
//! These are intentionally generic. The goal is to help a tester understand
//! WHY a check fires and which class of technique (hooking, repackaging,
//! property spoofing, etc.) bypasses it — not to provide a ready-to-run bypass
//! for any specific app.

pub fn lookup(key: &str) -> Option<&'static str> {
    match key {
        "root-hide-magisk" => Some(
            "Use Magisk's DenyList (or Shamiko on Zygisk-enabled builds) to hide Magisk from the target process. \
             Some apps additionally scan /proc/self/maps for libmagisk — pair DenyList with `magiskhide`-style \
             map scrubbing. If only the su binary is checked, a renamed su in a non-standard path may suffice."
        ),
        "rootbeer-hook" => Some(
            "RootBeer's checks are static methods. Hook `com.scottyab.rootbeer.RootBeer.isRooted()` (and \
             `RootBeerNative.checkForRoot()` if present) to return false via Frida/Xposed. The library does \
             not self-verify, so a single hook covers all checks."
        ),
        "play-integrity-spoof" => Some(
            "Play Integrity tokens are issued by Google Play Services. Bypassing requires either: (a) Play \
             Integrity Fix Magisk module (replaces device-integrity verdict), or (b) a custom Play Services \
             build with patched attestation. For QA: use a device that passes device-integrity by default \
             and only breaks on app-integrity or licensing checks."
        ),
        "rasp-runtime-hook" => Some(
            "RASP SDKs (Promon SHIELD, OneSpan App Shield, etc.) integrate at the native layer and call \
             abort()/exit() on detection. Bypass typically requires: (1) early instrumentation before the \
             RASP module loads (e.g. Frida spawn + early hook), (2) identifying the detection function via \
             the RASP's logs, (3) returning a clean verdict. This is non-trivial — budget significant time."
        ),
        "signature-spoof-xposed" => Some(
            "Repackage-signature checks call PackageManager.getPackageInfo(..., GET_SIGNATURES). Hook the \
             PackageManager API to return the original signing certificate (which you captured from the \
             unmodified APK before repackaging). The Xposed module ' signaturespoof ' or a Frida hook on \
             `getPackageInfo` both work."
        ),
        "self-integrity-redirect" => Some(
            "Self-integrity checks read /data/app/<pkg>/base.apk and hash it. Bypass by: (a) hooking the \
             `File`, `FileInputStream`, or `MessageDigest` calls to return the original APK bytes, or \
             (b) using a Magisk module that overlay-redirects the APK path. Approach (a) is more reliable."
        ),
        "dex-crc-patch" => Some(
            "DEX CRC checks read the `checksum` field of the DEX header. After patching bytecode, recompute \
             the Adler32 of everything after the checksum field and write it back. Then update the SHA-1 \
             signature in the DEX header. Tools: `dexopt`-aware patchers, or roll your own with `apktool` \
             rebuild + manual header patch."
        ),
        "frida-non-default-port" => Some(
            "Default-port detection is trivially bypassed: launch `frida-server` with `-l 0.0.0.0:<custom-port>` \
             and connect via `frida -H <host>:<port>`. For process-name scans, rename the `frida-server` \
             binary. For /proc/self/maps scans, use `frida-gadget` embedded mode or `hluda-cli` to strip \
             Frida symbols from the agent."
        ),
        "clone-pkg-rename" => Some(
            "Hardcoded package-name self-checks compare `getPackageName()` against a string. Hook \
             `Context.getPackageName()` (and `ApplicationInfo.packageName`) to return the original package \
             name. If the check is inside native code, hook the JNI binding or use a virtualization \
             framework that fakes the package name to the guest."
        ),
        _ => None,
    }
}
