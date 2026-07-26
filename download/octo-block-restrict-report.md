# APK Detector Report — Block/Restrict Filter

**Filter:** showing only findings whose runtime behavior would **force the app to stop, block the user from proceeding, or close access to features** (behavior: `process_kill` / `hard_block` / `soft_block`). Findings with `log_only` or `unknown` behavior are hidden — they record telemetry but do not impact the user. Use the full report to review them.

**Engine:** APK Detector v0.1.0
**Target:** `/tmp/my-project/apk-analysis/unpacked/base.apk`
**Size:** 159298425 bytes
**Rules loaded:** 57
**Findings:** 27 total (25 block/restrict, 2 hidden by filter)

## Summary by Category (Block/Restrict Only)

| Category | Findings | Highest severity |
|---|---:|---|
| Root Detection | 2 | medium |
| Play Integrity | 3 | high |
| Anti-Tamper | 4 | high |
| Anti-Hooking | 1 | high |
| Anti-Emulator | 5 | high |
| Clone / Repackage | 1 | medium |
| App Defense | 9 | high |

## Detailed Findings (Block/Restrict Only)

### Root Detection (2 findings)

**🟡 MEDIUM** `root-check-su-binary` _(hard_block)_
: su binary path check

- Evidence: `DEX string match: `/data/local/bin/su`, `/data/local/su`, `/data/local/xbin/su``
- **Bypass hint:** Use Magisk's DenyList (or Shamiko on Zygisk-enabled builds) to hide Magisk from the target process. Some apps additionally scan /proc/self/maps for libmagisk — pair DenyList with `magiskhide`-style map scrubbing. If only the su binary is checked, a renamed su in a non-standard path may suffice.
- Description: Looks for the su binary at well-known filesystem paths.

**🟢 LOW** `root-check-ro-secure-prop` _(hard_block)_
: ro.secure / ro.debuggable property check

- Evidence: `DEX string match: `ro.debuggable`, `ro.secureboot.lockstate``
- Description: Reads SystemProperties for signs of a non-stock build.

### Play Integrity (3 findings)

**🟠 HIGH** `play-integrity-api-call` _(hard_block)_
: Play Integrity API request

- Evidence: `DEX string match: `ExpressIntegrityService`, `IntegrityService`, `Lcom/google/android/play/core/integrity/IntegrityServiceException;``
- **Bypass hint:** Play Integrity tokens are issued by Google Play Services. Bypassing requires either: (a) Play Integrity Fix Magisk module (replaces device-integrity verdict), or (b) a custom Play Services build with patched attestation. For QA: use a device that passes device-integrity by default and only breaks on app-integrity or licensing checks.
- Description: Calls Google Play Integrity API to verify device + app authenticity.

**🟠 HIGH** `play-integrity-manager-impl` _(hard_block)_
: Integrity token verification

- Evidence: `DEX string match: `Lcom/google/android/play/core/integrity/IntegrityTokenResponse;``
- Description: Verifies the integrity token returned by Play Services.

**🟡 MEDIUM** `play-integrity-safety-net-legacy` _(hard_block)_
: Legacy SafetyNet attestation

- Evidence: `DEX string match: `attestation object missing authData`, `attestationObject`, `failed to parse attestation object``
- Description: Uses the deprecated SafetyNet Attestation API (pre-Play-Integrity).

### Anti-Tamper (4 findings)

**🟠 HIGH** `anti-tamper-pm-get-signatures-v2` _(hard_block)_
: PackageManager GET_SIGNING_CERTIFICATES (v2+)

- Evidence: `DEX string match: `getSigningInfo``
- Description: Uses the API 28+ signing-info API to verify the APK's v2/v3 signature.

**🟠 HIGH** `anti-tamper-self-integrity` _(hard_block)_
: APK self-integrity check

- Evidence: `DEX string match: `.apk`, `(_\d+)?\.apk`, `.apk``
- **Bypass hint:** Self-integrity checks read /data/app/<pkg>/base.apk and hash it. Bypass by: (a) hooking the `File`, `FileInputStream`, or `MessageDigest` calls to return the original APK bytes, or (b) using a Magisk module that overlay-redirects the APK path. Approach (a) is more reliable.
- Description: Computes a hash of the APK file at runtime and compares against expected value.

**🟠 HIGH** `anti-tamper-signature-get-installed` _(hard_block)_
: PackageManager.GET_SIGNATURES

- Evidence: `DEX string match: `getInstalledPackages`, `getPackageInfo`, `Lcom/datadog/android/core/internal/CoreFeature$getPackageInfo$2;``
- **Bypass hint:** Repackage-signature checks call PackageManager.getPackageInfo(..., GET_SIGNATURES). Hook the PackageManager API to return the original signing certificate (which you captured from the unmodified APK before repackaging). The Xposed module ' signaturespoof ' or a Frida hook on `getPackageInfo` both work.
- Description: Reads signing certificate to detect repackaging. (Common — also used by benign apps.)

**🟡 MEDIUM** `anti-tamper-dex-crc` _(hard_block)_
: DEX CRC sanity check

- Evidence: `DEX string match: `Ljava/util/zip/CRC32;`, `Ljava/util/zip/Adler32;`, `CRC32``
- **Bypass hint:** DEX CRC checks read the `checksum` field of the DEX header. After patching bytecode, recompute the Adler32 of everything after the checksum field and write it back. Then update the SHA-1 signature in the DEX header. Tools: `dexopt`-aware patchers, or roll your own with `apktool` rebuild + manual header patch.
- Description: Computes DEX CRC at runtime to detect bytecode modification.

### Anti-Hooking (1 finding)

**🟠 HIGH** `anti-hook-frida-maps-scan` _(hard_block)_
: Frida maps scan

- Evidence: `DEX string match: `blackfriday`, `frida`, `frida detection error``
- Description: Reads /proc/self/maps for Frida shared-object fingerprints.

### Anti-Emulator (5 findings)

**🟠 HIGH** `anti-emulator-bluestacks` _(hard_block)_
: BlueStacks / Nox / LDPlayer markers

- Evidence: `DEX string match: ` without KNOX.`, `KNOX``
- Description: Detects desktop Android emulators (BlueStacks, Nox, LDPlayer).

**🟠 HIGH** `anti-emulator-files` _(hard_block)_
: Emulator-specific file check

- Evidence: `DEX string match: `/dev/qemu_pipe`, `/dev/socket/qemud`, `/proc/cpuinfo``
- Description: Touches filesystem paths that only exist on QEMU/emulator images.

**🟡 MEDIUM** `anti-emulator-build-fingerprint` _(hard_block)_
: Build.FINGERPRINT substring check

- Evidence: `DEX string match: ` is unknown to the FragmentNavigator. Please use the navigate() function to add fragments to the FragmentNavigator managed FragmentManager.`, ` unknown`, ` unknown tag ``
- Description: Checks Build.FINGERPRINT/MODEL/PRODUCT for emulator markers.

**🟡 MEDIUM** `anti-emulator-network` _(hard_block)_
: Emulator network probe

- Evidence: `DEX string match: `/sys/class/net/eth0/address``
- Description: Checks IP/iface for default emulator networking.

**🟡 MEDIUM** `anti-emulator-telephony` _(hard_block)_
: Telephony emulator markers

- Evidence: `DEX string match: `Landroid/telephony/TelephonyManager$CellInfoCallback;`, `Landroid/telephony/TelephonyManager;`, `getSubscriberId``
- Description: Probes TelephonyManager — emulator returns well-known dummy values.

### Clone / Repackage (1 finding)

**🟡 MEDIUM** `clone-installer-source` _(hard_block)_
: Installer source check

- Evidence: `DEX string match: `com.android.vending.INSTALL_REFERRER`, `getInstallerPackageName`, `com.android.vending``
- Description: Checks which app store installed the APK — used to reject sideloaded clones.

### App Defense (9 findings)

**🟠 HIGH** `app-defense-accessibility` _(hard_block)_
: Accessibility-service abuse defense

- Evidence: `DEX string match: `Landroid/accessibilityservice/AccessibilityServiceInfo;`, `Landroid/view/accessibility/AccessibilityManager$AccessibilityServicesStateChangeListener;`, `SMAP
AccessibilityServiceSta…`
- **Bypass hint:** Accessibility-service detection enumerates `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` or calls `AccessibilityManager.getEnabledAccessibilityServiceList`. Bypass: (a) disable the third-party accessibility service before launching the app; (b) hook `AccessibilityManager.getEnabledAccessibilityServiceList` to filter the list to only system services; (c) hook `Settings.Secure.getString` to return a filtered list for the `ENABLED_ACCESSIBILITY_SERVICES` key. Note: system TalkBack is usually allow-listed.
- Description: Blocks screen-reading / auto-clicker accessibility services — banking-trojan defense.

**🟠 HIGH** `app-defense-anti-debug` _(hard_block)_
: Debugger detection

- Evidence: `DEX string match: `isDebuggerConnected`, `/proc/self/status`, `isDebuggerConnected``
- **Bypass hint:** Anti-debugger checks read `Debug.isDebuggerConnected()` and `/proc/self/status` (TracerPid field). Bypass: (a) attach with Frida in spawn mode (not attach mode) — `frida -U -f <pkg> --no-pause`, which gives you control before the check runs; (b) hook `android.os.Debug.isDebuggerConnected` to return false; (c) hook the `FileInputStream` read on `/proc/self/status` and rewrite the TracerPid line to `0`. For ptrace-based checks, ptrace yourself with a dummy child process to make `PTRACE_ATTACH` fail (the classic `prctl(PR_SET_DUMPABLE, 0)` trick).
- Description: Detects attached debuggers via android.os.Debug + /proc/self/status TracerPid scan.

**🟠 HIGH** `app-defense-drm-attestation` _(hard_block)_
: Widevine DRM attestation check

- Evidence: `DEX string match: `L1`, `Landroid/media/MediaDrm;`, `Landroid/opengl/EGL14;``
- **Bypass hint:** Widevine DRM attestation queries `MediaDrm.getPropertyByteArray("deviceUniqueId")` and inspects the DRM level (L1 = hardware-backed, L3 = software only). Bypass: (a) on a real device with Widevine L1, no bypass needed; (b) on emulators (L3 only), spoof the MediaDrm properties via Frida hook on `MediaDrm.getPropertyByteArray`; (c) for full attestation, you cannot bypass the cryptographic chain without a valid L1 device — use a real device that passes the check.
- Description: Queries MediaDrm for Widevine L1/L3 attestation — strong hardware-identity signal.

**🟠 HIGH** `app-defense-knox-tima` _(hard_block)_
: Samsung KNOX / TIMA attestation

- Evidence: `DEX string match: `FLEXIBLE_LEGITIMATE_INTEREST`, `LEGITIMATE_INTEREST`, `PURPOSE_RESTRICTION_REQUIRE_LEGITIMATE_INTEREST``
- **Bypass hint:** Samsung KNOX TIMA attestation requires a Samsung device with KNOX hardware. Bypass: (a) use a Samsung device — the check passes natively; (b) on non-Samsung devices, the API call itself throws ClassNotFoundException — hook the ClassLoader to swallow the lookup; (c) for full TIMA chain verification, you cannot bypass without Samsung hardware. Most apps fall back to a weaker check when KNOX is unavailable — target the fallback instead.
- Description: Samsung KNOX TIMA attestation — only fires on Samsung devices but very strong signal when present.

**🟡 MEDIUM** `app-defense-debug-flag` _(hard_block)_
: ro.debuggable / developer-options flag check

- Evidence: `DEX string match: `ro.debuggable``
- **Bypass hint:** Developer-options checks read `Settings.Global.ADB_ENABLED` and `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`. Bypass: (a) turn off Developer Options in Settings before launching the app; (b) hook `Settings.Global.getInt` to return 0 for these specific keys; (c) on rooted devices, use a Magisk module that toggles the Settings.Global provider entries back to 0 just for the target app.
- Description: Reads system properties / Settings.Global for signs of a debug build or enabled developer options.

**🟡 MEDIUM** `app-defense-mediaprojection` _(hard_block)_
: MediaProjection / screen-recording defense

- Evidence: `DEX string match: `Landroid/media/projection/MediaProjection$Callback;`, `Landroid/media/projection/MediaProjection;`, `Landroid/media/projection/MediaProjectionManager;``
- **Bypass hint:** MediaProjection detection checks for an active `MediaProjection` session, often via `MediaProjectionManager` callbacks or by looking for `createVirtualDisplay` activity. Bypass: (a) stop the screen recorder / screenshot app before launching the target; (b) the app also commonly sets `FLAG_SECURE` on sensitive Activities — to bypass FLAG_SECURE, hook `Window.setFlags` to clear the FLAG_SECURE bit, or use a Magisk module like `FlagSecureBypass`.
- Description: Detects active screen capture via MediaProjection API; often paired with FLAG_SECURE.

**🟡 MEDIUM** `app-defense-mock-location` _(soft_block)_
: Mock location detection

- Evidence: `DEX string match: `KEY_MOCK_LOCATION`, `isFromMockProvider`, `KEY_MOCK_LOCATION``
- **Bypass hint:** Mock-location checks call `Location.isFromMockProvider()`. Bypass: (a) hook `Location.isFromMockProvider` to return false via Frida; (b) on Android 12+ use a root-based GPS spoofer that writes directly to the location HAL rather than using the mock-location API (which `isFromMockProvider` cannot detect); (c) on older Android, use Xposed's `MockLocationEnabler` module which strips the mock flag.
- Description: Detects spoofed GPS via Location.isFromMockProvider() — common in fraud / geo-restricted apps.

**🟡 MEDIUM** `app-defense-play-services-presence` _(soft_block)_
: Google Play Services presence + version check

- Evidence: `DEX string match: `GoogleApiAvailability`, `Lcom/google/android/gms/common/GoogleApiAvailability;`, `Missing resolution for ConnectionResult.RESOLUTION_REQUIRED. Call GoogleApiAvailability#showErrorNo…`
- **Bypass hint:** Play Services presence checks call `GoogleApiAvailability.isGooglePlayServicesAvailable` and expect `ConnectionResult.SUCCESS`. Bypass: (a) install/upgrade Google Play Services on the device (impossible on AOSP / degoogled ROMs without microG); (b) install microG — most apps accept microG's signature spoofing as valid Play Services; (c) hook `GoogleApiAvailability.isGooglePlayServicesAvailable` to return `ConnectionResult.SUCCESS` via Frida/Xposed.
- Description: Requires Google Play Services to be installed + up-to-date — blocks AOSP / degoogled ROMs.

**🟡 MEDIUM** `app-defense-vpn` _(soft_block)_
: VPN interface detection

- Evidence: `DEX string match: `tun0``
- **Bypass hint:** VPN detection scans `NetworkCapabilities` for `TRANSPORT_VPN` or lists network interfaces for `tun0`/`tun1`. Bypass: (a) disconnect the VPN before launching the app; (b) hook `ConnectivityManager.getNetworkCapabilities` to strip the VPN transport; (c) hook `NetworkInterface.getNetworkInterfaces` to filter out `tun0`. For root users: route the app through a VPN namespace the app cannot see via `ip netns`.
- Description: Checks for active VPN tunnel — used to block users on VPNs (geo-fencing / fraud-defense).

