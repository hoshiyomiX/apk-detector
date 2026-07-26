# APK Detector — Device Simulation Report

**Engine:** APK Detector v0.1.0
**Target APK:** `/tmp/my-project/apk-analysis/unpacked/base.apk`
**Device profile:** `{"rooted":false,"magisk_denylist_on":false,"play_integrity_passes":false,"safetynet_passes":false,"installer_is_play_store":false,"in_clone_runtime":false,"is_emulator":true,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":true,"developer_options_on":true,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}`
**Findings:** 27 total — 15 triggered, 12 bypassed, 0 unknown

## Summary

| Verdict | Count | Meaning |
|---|---:|---|
| 🔴 Triggered | 15 | Detection fires on this device — user is blocked/restricted |
| 🟢 Bypassed  | 12 | Detection rule exists but user's setup defeats it |
| ⚪ Unknown   | 0 | Simulator has no mapping, or profile field is unset |

## Detailed Simulation

### 🔴 Triggered (15 findings)

**🟢 LOW** `anti-emulator-build-manufacturer`
: Build.MANUFACTURER/BRAND check

- Why it triggers: Build.* fields carry emulator defaults (unknown, google, goldfish_arm64, ...).

**🟠 HIGH** `anti-emulator-files`
: Emulator-specific file check

- Why it triggers: Emulator-only filesystem paths exist (qemud socket, qemu_pipe, libc_malloc_debug_qemu.so).

**🟠 HIGH** `app-defense-anti-debug`
: Debugger detection

- Why it triggers: Debugger attached — Debug.isDebuggerConnected() == true OR TracerPid != 0 in /proc/self/status.
- **Bypass hint:** Anti-debugger checks read `Debug.isDebuggerConnected()` and `/proc/self/status` (TracerPid field). Bypass: (a) attach with Frida in spawn mode (not attach mode) — `frida -U -f <pkg> --no-pause`, which gives you control before the check runs; (b) hook `android.os.Debug.isDebuggerConnected` to return false; (c) hook the `FileInputStream` read on `/proc/self/status` and rewrite the TracerPid line to `0`. For ptrace-based checks, ptrace yourself with a dummy child process to make `PTRACE_ATTACH` fail (the classic `prctl(PR_SET_DUMPABLE, 0)` trick).

**🟠 HIGH** `play-integrity-manager-impl`
: Integrity token verification

- Why it triggers: Token verification fails — IntegrityTokenResponse carries an error verdict.

**🟠 HIGH** `app-defense-drm-attestation`
: Widevine DRM attestation check

- Why it triggers: Emulator reports Widevine L3 only — MediaDrm attestation is weak, app rejects.
- **Bypass hint:** Widevine DRM attestation queries `MediaDrm.getPropertyByteArray("deviceUniqueId")` and inspects the DRM level (L1 = hardware-backed, L3 = software only). Bypass: (a) on a real device with Widevine L1, no bypass needed; (b) on emulators (L3 only), spoof the MediaDrm properties via Frida hook on `MediaDrm.getPropertyByteArray`; (c) for full attestation, you cannot bypass the cryptographic chain without a valid L1 device — use a real device that passes the check.

**🟠 HIGH** `play-integrity-api-call`
: Play Integrity API request

- Why it triggers: Play Integrity API call returns a verdict missing DEVICE_INTEGRITY — app rejects.
- **Bypass hint:** Play Integrity tokens are issued by Google Play Services. Bypassing requires either: (a) Play Integrity Fix Magisk module (replaces device-integrity verdict), or (b) a custom Play Services build with patched attestation. For QA: use a device that passes device-integrity by default and only breaks on app-integrity or licensing checks.

**🟡 MEDIUM** `clone-installer-source`
: Installer source check

- Why it triggers: getInstallerPackageName() returns null or a non-Play installer — sideloaded clone suspected.

**🟡 MEDIUM** `anti-emulator-build-fingerprint`
: Build.FINGERPRINT substring check

- Why it triggers: Build.FINGERPRINT contains emulator markers (generic_x86, sdk_gphone, google_sdk, ...).

**🟠 HIGH** `app-defense-knox-tima`
: Samsung KNOX / TIMA attestation

- Why it triggers: Device is not Samsung — KNOX TIMA attestation API call will fail (or app falls back to weaker check).
- **Bypass hint:** Samsung KNOX TIMA attestation requires a Samsung device with KNOX hardware. Bypass: (a) use a Samsung device — the check passes natively; (b) on non-Samsung devices, the API call itself throws ClassNotFoundException — hook the ClassLoader to swallow the lookup; (c) for full TIMA chain verification, you cannot bypass without Samsung hardware. Most apps fall back to a weaker check when KNOX is unavailable — target the fallback instead.

**🟡 MEDIUM** `anti-emulator-sensors`
: Sensor / hardware presence check

- Why it triggers: Emulator sensors are absent or return constant values (TYPE_ACCELEROMETER reports 0.0).

**🟡 MEDIUM** `play-integrity-safety-net-legacy`
: Legacy SafetyNet attestation

- Why it triggers: SafetyNet returns BASIC_INTTEGRITY but fails CTS_PROFILE_MATCH — app rejects.

**🟡 MEDIUM** `anti-emulator-network`
: Emulator network probe

- Why it triggers: Emulator network probes return default values (10.0.2.15 IP, eth0 iface).

**🟡 MEDIUM** `app-defense-debug-flag`
: ro.debuggable / developer-options flag check

- Why it triggers: Developer options enabled — Settings.Global.ADB_ENABLED=1 OR DEVELOPMENT_SETTINGS_ENABLED=1.
- **Bypass hint:** Developer-options checks read `Settings.Global.ADB_ENABLED` and `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`. Bypass: (a) turn off Developer Options in Settings before launching the app; (b) hook `Settings.Global.getInt` to return 0 for these specific keys; (c) on rooted devices, use a Magisk module that toggles the Settings.Global provider entries back to 0 just for the target app.

**🟡 MEDIUM** `anti-emulator-telephony`
: Telephony emulator markers

- Why it triggers: TelephonyManager.getDeviceId() returns emulator dummy (15555215554, null).

**🟠 HIGH** `anti-emulator-bluestacks`
: BlueStacks / Nox / LDPlayer markers

- Why it triggers: /sys/class/dmi/id/sys_vendor matches BlueStacks/Nox/LDPlayer vendor strings.

### 🟢 Bypassed (12 findings)

**🟠 HIGH** `anti-tamper-self-integrity`
: APK self-integrity check

- How it's bypassed: APK file hash matches the expected value — self-integrity check passes.

**🟢 LOW** `root-check-ro-secure-prop`
: ro.secure / ro.debuggable property check

- How it's bypassed: ro.secure=1 on stock builds — check does not fire.

**🟡 MEDIUM** `anti-tamper-dex-crc`
: DEX CRC sanity check

- How it's bypassed: DEX CRC matches the value stored in the DEX header — check passes.

**🟠 HIGH** `anti-hook-frida-maps-scan`
: Frida maps scan

- How it's bypassed: No Frida agent loaded — /proc/self/maps contains no frida-agent.so entry.

**🟠 HIGH** `anti-tamper-pm-get-signatures-v2`
: PackageManager GET_SIGNING_CERTIFICATES (v2+)

- How it's bypassed: APK signature matches the original — PackageManager.getSigningInfo() returns the expected cert.

**🟡 MEDIUM** `app-defense-mock-location`
: Mock location detection

- How it's bypassed: Location.isFromMockProvider() returns false for all locations.

**🟡 MEDIUM** `app-defense-mediaprojection`
: MediaProjection / screen-recording defense

- How it's bypassed: No active MediaProjection session — screen is not being captured.

**🟠 HIGH** `anti-tamper-signature-get-installed`
: PackageManager.GET_SIGNATURES

- How it's bypassed: getInstalledPackages returns the original signature — check passes.

**🟡 MEDIUM** `root-check-su-binary`
: su binary path check

- How it's bypassed: Device is not rooted — su binary does not exist.

**🟡 MEDIUM** `app-defense-vpn`
: VPN interface detection

- How it's bypassed: No tun0/tun1 interface present — NetworkCapabilities has no TRANSPORT_VPN.

**🟠 HIGH** `app-defense-accessibility`
: Accessibility-service abuse defense

- How it's bypassed: No non-system accessibility service enabled — getEnabledAccessibilityServiceList() returns empty.

**🟡 MEDIUM** `app-defense-play-services-presence`
: Google Play Services presence + version check

- How it's bypassed: Google Play Services installed and up-to-date — isGooglePlayServicesAvailable() returns SUCCESS.

