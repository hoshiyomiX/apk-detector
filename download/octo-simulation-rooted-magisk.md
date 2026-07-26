# APK Detector — Device Simulation Report

**Engine:** APK Detector v0.1.0
**Target APK:** `/tmp/my-project/apk-analysis/unpacked/base.apk`
**Device profile:** `{"rooted":true,"magisk_denylist_on":true,"play_integrity_passes":true,"safetynet_passes":true,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":false,"developer_options_on":false,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}`
**Findings:** 27 total — 2 triggered, 25 bypassed, 0 unknown

## Summary

| Verdict | Count | Meaning |
|---|---:|---|
| 🔴 Triggered | 2 | Detection fires on this device — user is blocked/restricted |
| 🟢 Bypassed  | 25 | Detection rule exists but user's setup defeats it |
| ⚪ Unknown   | 0 | Simulator has no mapping, or profile field is unset |

## Detailed Simulation

### 🔴 Triggered (2 findings)

**🟢 LOW** `root-check-ro-secure-prop`
: ro.secure / ro.debuggable property check

- Why it triggers: Rooted builds often flip ro.secure=0 or ro.debuggable=1, which this check detects.

**🟠 HIGH** `app-defense-knox-tima`
: Samsung KNOX / TIMA attestation

- Why it triggers: Device is not Samsung — KNOX TIMA attestation API call will fail (or app falls back to weaker check).
- **Bypass hint:** Samsung KNOX TIMA attestation requires a Samsung device with KNOX hardware. Bypass: (a) use a Samsung device — the check passes natively; (b) on non-Samsung devices, the API call itself throws ClassNotFoundException — hook the ClassLoader to swallow the lookup; (c) for full TIMA chain verification, you cannot bypass without Samsung hardware. Most apps fall back to a weaker check when KNOX is unavailable — target the fallback instead.

### 🟢 Bypassed (25 findings)

**🟡 MEDIUM** `app-defense-mock-location`
: Mock location detection

- How it's bypassed: Location.isFromMockProvider() returns false for all locations.

**🟡 MEDIUM** `root-check-su-binary`
: su binary path check

- How it's bypassed: Magisk DenyList hides the su binary + Magisk's mount namespaces from this process.

**🟡 MEDIUM** `anti-tamper-dex-crc`
: DEX CRC sanity check

- How it's bypassed: DEX CRC matches the value stored in the DEX header — check passes.

**🟠 HIGH** `anti-tamper-signature-get-installed`
: PackageManager.GET_SIGNATURES

- How it's bypassed: getInstalledPackages returns the original signature — check passes.

**🟠 HIGH** `play-integrity-manager-impl`
: Integrity token verification

- How it's bypassed: Integrity token decodes cleanly — device-integrity + app-integrity both pass.

**🟢 LOW** `anti-emulator-build-manufacturer`
: Build.MANUFACTURER/BRAND check

- How it's bypassed: Build.MANUFACTURER/BRAND/HARDWARE/MODEL are real-device values.

**🟠 HIGH** `anti-tamper-self-integrity`
: APK self-integrity check

- How it's bypassed: APK file hash matches the expected value — self-integrity check passes.

**🟠 HIGH** `anti-emulator-bluestacks`
: BlueStacks / Nox / LDPlayer markers

- How it's bypassed: DMI sys_vendor does not match BlueStacks/Nox/LDPlayer signatures.

**🟡 MEDIUM** `app-defense-mediaprojection`
: MediaProjection / screen-recording defense

- How it's bypassed: No active MediaProjection session — screen is not being captured.

**🟡 MEDIUM** `app-defense-play-services-presence`
: Google Play Services presence + version check

- How it's bypassed: Google Play Services installed and up-to-date — isGooglePlayServicesAvailable() returns SUCCESS.

**🟡 MEDIUM** `play-integrity-safety-net-legacy`
: Legacy SafetyNet attestation

- How it's bypassed: SafetyNet attestation passes CTS profile match.

**🟡 MEDIUM** `app-defense-debug-flag`
: ro.debuggable / developer-options flag check

- How it's bypassed: Settings.Global.ADB_ENABLED=0 and DEVELOPMENT_SETTINGS_ENABLED=0.

**🟠 HIGH** `app-defense-drm-attestation`
: Widevine DRM attestation check

- How it's bypassed: Widevine L3 on a real device is acceptable for most apps (only fails if app strictly requires L1).

**🟡 MEDIUM** `clone-installer-source`
: Installer source check

- How it's bypassed: getInstallerPackageName() returns com.android.vending — installed from Play Store.

**🟡 MEDIUM** `anti-emulator-build-fingerprint`
: Build.FINGERPRINT substring check

- How it's bypassed: Build.FINGERPRINT is a real device string (e.g. samsung/star2q5g/x1q...).

**🟠 HIGH** `anti-emulator-files`
: Emulator-specific file check

- How it's bypassed: /dev/socket/qemud, /dev/qemu_pipe, etc. do not exist on real devices.

**🟠 HIGH** `anti-tamper-pm-get-signatures-v2`
: PackageManager GET_SIGNING_CERTIFICATES (v2+)

- How it's bypassed: APK signature matches the original — PackageManager.getSigningInfo() returns the expected cert.

**🟡 MEDIUM** `anti-emulator-sensors`
: Sensor / hardware presence check

- How it's bypassed: Real accelerometers / gyroscopes are present and return non-default values.

**🟡 MEDIUM** `app-defense-vpn`
: VPN interface detection

- How it's bypassed: No tun0/tun1 interface present — NetworkCapabilities has no TRANSPORT_VPN.

**🟡 MEDIUM** `anti-emulator-network`
: Emulator network probe

- How it's bypassed: Network interfaces do not include emulator defaults (10.0.2.15, eth0 routing).

**🟠 HIGH** `app-defense-accessibility`
: Accessibility-service abuse defense

- How it's bypassed: No non-system accessibility service enabled — getEnabledAccessibilityServiceList() returns empty.

**🟠 HIGH** `app-defense-anti-debug`
: Debugger detection

- How it's bypassed: Debug.isDebuggerConnected() returns false and /proc/self/status TracerPid is 0.

**🟠 HIGH** `anti-hook-frida-maps-scan`
: Frida maps scan

- How it's bypassed: No Frida agent loaded — /proc/self/maps contains no frida-agent.so entry.

**🟠 HIGH** `play-integrity-api-call`
: Play Integrity API request

- How it's bypassed: Device passes Play Integrity (Play Integrity Fix module or stock device). API returns DEVICE_INTEGRITY.

**🟡 MEDIUM** `anti-emulator-telephony`
: Telephony emulator markers

- How it's bypassed: TelephonyManager returns real device values.

