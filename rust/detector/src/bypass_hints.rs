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
        "app-defense-anti-debug" => Some(
            "Anti-debugger checks read `Debug.isDebuggerConnected()` and `/proc/self/status` \
             (TracerPid field). Bypass: (a) attach with Frida in spawn mode (not attach mode) — \
             `frida -U -f <pkg> --no-pause`, which gives you control before the check runs; \
             (b) hook `android.os.Debug.isDebuggerConnected` to return false; (c) hook the \
             `FileInputStream` read on `/proc/self/status` and rewrite the TracerPid line to `0`. \
             For ptrace-based checks, ptrace yourself with a dummy child process to make \
             `PTRACE_ATTACH` fail (the classic `prctl(PR_SET_DUMPABLE, 0)` trick)."
        ),
        "app-defense-debug-flag" => Some(
            "Developer-options checks read `Settings.Global.ADB_ENABLED` and \
             `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`. Bypass: (a) turn off Developer \
             Options in Settings before launching the app; (b) hook `Settings.Global.getInt` \
             to return 0 for these specific keys; (c) on rooted devices, use a Magisk module \
             that toggles the Settings.Global provider entries back to 0 just for the target app."
        ),
        "app-defense-vpn" => Some(
            "VPN detection scans `NetworkCapabilities` for `TRANSPORT_VPN` or lists network \
             interfaces for `tun0`/`tun1`. Bypass: (a) disconnect the VPN before launching the \
             app; (b) hook `ConnectivityManager.getNetworkCapabilities` to strip the VPN \
             transport; (c) hook `NetworkInterface.getNetworkInterfaces` to filter out `tun0`. \
             For root users: route the app through a VPN namespace the app cannot see via \
             `ip netns`."
        ),
        "app-defense-mock-location" => Some(
            "Mock-location checks call `Location.isFromMockProvider()`. Bypass: (a) hook \
             `Location.isFromMockProvider` to return false via Frida; (b) on Android 12+ use \
             a root-based GPS spoofer that writes directly to the location HAL rather than \
             using the mock-location API (which `isFromMockProvider` cannot detect); \
             (c) on older Android, use Xposed's `MockLocationEnabler` module which strips the \
             mock flag."
        ),
        "app-defense-accessibility" => Some(
            "Accessibility-service detection enumerates `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` \
             or calls `AccessibilityManager.getEnabledAccessibilityServiceList`. Bypass: (a) disable \
             the third-party accessibility service before launching the app; (b) hook \
             `AccessibilityManager.getEnabledAccessibilityServiceList` to filter the list to only \
             system services; (c) hook `Settings.Secure.getString` to return a filtered list for \
             the `ENABLED_ACCESSIBILITY_SERVICES` key. Note: system TalkBack is usually allow-listed."
        ),
        "app-defense-mediaprojection" => Some(
            "MediaProjection detection checks for an active `MediaProjection` session, often via \
             `MediaProjectionManager` callbacks or by looking for `createVirtualDisplay` activity. \
             Bypass: (a) stop the screen recorder / screenshot app before launching the target; \
             (b) the app also commonly sets `FLAG_SECURE` on sensitive Activities — to bypass \
             FLAG_SECURE, hook `Window.setFlags` to clear the FLAG_SECURE bit, or use a Magisk \
             module like `FlagSecureBypass`."
        ),
        "app-defense-drm-attestation" => Some(
            "Widevine DRM attestation queries `MediaDrm.getPropertyByteArray(\"deviceUniqueId\")` \
             and inspects the DRM level (L1 = hardware-backed, L3 = software only). Bypass: \
             (a) on a real device with Widevine L1, no bypass needed; (b) on emulators (L3 only), \
             spoof the MediaDrm properties via Frida hook on `MediaDrm.getPropertyByteArray`; \
             (c) for full attestation, you cannot bypass the cryptographic chain without a \
             valid L1 device — use a real device that passes the check."
        ),
        "app-defense-knox-tima" => Some(
            "Samsung KNOX TIMA attestation requires a Samsung device with KNOX hardware. Bypass: \
             (a) use a Samsung device — the check passes natively; (b) on non-Samsung devices, \
             the API call itself throws ClassNotFoundException — hook the ClassLoader to swallow \
             the lookup; (c) for full TIMA chain verification, you cannot bypass without Samsung \
             hardware. Most apps fall back to a weaker check when KNOX is unavailable — target \
             the fallback instead."
        ),
        "app-defense-play-services-presence" => Some(
            "Play Services presence checks call `GoogleApiAvailability.isGooglePlayServicesAvailable` \
             and expect `ConnectionResult.SUCCESS`. Bypass: (a) install/upgrade Google Play \
             Services on the device (impossible on AOSP / degoogled ROMs without microG); \
             (b) install microG — most apps accept microG's signature spoofing as valid Play \
             Services; (c) hook `GoogleApiAvailability.isGooglePlayServicesAvailable` to return \
             `ConnectionResult.SUCCESS` via Frida/Xposed."
        ),
        _ => None,
    }
}
