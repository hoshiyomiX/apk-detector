# APK Detector Report — Block/Restrict Filter

**Filter:** showing only findings that would **block or restrict** the user (severity Medium / High / Critical). Low and Info findings are hidden — use the full report to review them.

**Engine:** APK Detector v0.1.0
**Target:** `/tmp/my-project/apk-analysis/unpacked/base.apk`
**Size:** 159298425 bytes
**Rules loaded:** 48
**Findings:** 18 total (16 block/restrict, 2 hidden by filter)

## Summary by Category (Block/Restrict Only)

| Category | Findings | Highest severity |
|---|---:|---|
| Root Detection | 1 | medium |
| Play Integrity | 3 | high |
| Anti-Tamper | 4 | high |
| Anti-Hooking | 1 | high |
| Anti-Emulator | 6 | high |
| Clone / Repackage | 1 | medium |

## Detailed Findings (Block/Restrict Only)

### Root Detection (1 finding)

**🟡 MEDIUM** `root-check-su-binary`
: su binary path check

- Evidence: `DEX string match: `/system/bin/su``
- **Bypass hint:** Use Magisk's DenyList (or Shamiko on Zygisk-enabled builds) to hide Magisk from the target process. Some apps additionally scan /proc/self/maps for libmagisk — pair DenyList with `magiskhide`-style map scrubbing. If only the su binary is checked, a renamed su in a non-standard path may suffice.
- Description: Looks for the su binary at well-known filesystem paths.

### Play Integrity (3 findings)

**🟠 HIGH** `play-integrity-api-call`
: Play Integrity API request

- Evidence: `DEX string match: `com.google.android.play.core.integrity.protocol.IExpressIntegrityService`, `com.google.android.play.core.integrity.protocol.IExpressIntegrityServiceCallback`, `com.google.android.pl…`
- **Bypass hint:** Play Integrity tokens are issued by Google Play Services. Bypassing requires either: (a) Play Integrity Fix Magisk module (replaces device-integrity verdict), or (b) a custom Play Services build with patched attestation. For QA: use a device that passes device-integrity by default and only breaks on app-integrity or licensing checks.
- Description: Calls Google Play Integrity API to verify device + app authenticity.

**🟠 HIGH** `play-integrity-manager-impl`
: Integrity token verification

- Evidence: `DEX string match: `Lcom/google/android/play/core/integrity/IntegrityTokenResponse;``
- Description: Verifies the integrity token returned by Play Services.

**🟡 MEDIUM** `play-integrity-safety-net-legacy`
: Legacy SafetyNet attestation

- Evidence: `DEX string match: `Lcom/google/android/gms/safetynet/SafetyNetApi$VerifyAppsUserResponse;``
- Description: Uses the deprecated SafetyNet Attestation API (pre-Play-Integrity).

### Anti-Tamper (4 findings)

**🟠 HIGH** `anti-tamper-pm-get-signatures-v2`
: PackageManager GET_SIGNING_CERTIFICATES (v2+)

- Evidence: `DEX string match: `getSigningInfo``
- Description: Uses the API 28+ signing-info API to verify the APK's v2/v3 signature.

**🟠 HIGH** `anti-tamper-self-integrity`
: APK self-integrity check

- Evidence: `DEX string match: `(_\d+)?\.apk`, `.apk`, `/system/app/Superuser.apk``
- **Bypass hint:** Self-integrity checks read /data/app/<pkg>/base.apk and hash it. Bypass by: (a) hooking the `File`, `FileInputStream`, or `MessageDigest` calls to return the original APK bytes, or (b) using a Magisk module that overlay-redirects the APK path. Approach (a) is more reliable.
- Description: Computes a hash of the APK file at runtime and compares against expected value.

**🟠 HIGH** `anti-tamper-signature-get-installed`
: PackageManager.GET_SIGNATURES

- Evidence: `DEX string match: `getInstalledPackages``
- **Bypass hint:** Repackage-signature checks call PackageManager.getPackageInfo(..., GET_SIGNATURES). Hook the PackageManager API to return the original signing certificate (which you captured from the unmodified APK before repackaging). The Xposed module ' signaturespoof ' or a Frida hook on `getPackageInfo` both work.
- Description: Reads signing certificate to detect repackaging. (Common — also used by benign apps.)

**🟡 MEDIUM** `anti-tamper-dex-crc`
: DEX CRC sanity check

- Evidence: `DEX string match: `Ljava/util/zip/Adler32;``
- **Bypass hint:** DEX CRC checks read the `checksum` field of the DEX header. After patching bytecode, recompute the Adler32 of everything after the checksum field and write it back. Then update the SHA-1 signature in the DEX header. Tools: `dexopt`-aware patchers, or roll your own with `apktool` rebuild + manual header patch.
- Description: Computes DEX CRC at runtime to detect bytecode modification.

### Anti-Hooking (1 finding)

**🟠 HIGH** `anti-hook-frida-maps-scan`
: Frida maps scan

- Evidence: `DEX string match: `/proc/self/maps``
- Description: Reads /proc/self/maps for Frida shared-object fingerprints.

### Anti-Emulator (6 findings)

**🟠 HIGH** `anti-emulator-bluestacks`
: BlueStacks / Nox / LDPlayer markers

- Evidence: `DEX string match: ` without KNOX.`, `KNOX``
- Description: Detects desktop Android emulators (BlueStacks, Nox, LDPlayer).

**🟠 HIGH** `anti-emulator-files`
: Emulator-specific file check

- Evidence: `DEX string match: `/dev/socket/qemud``
- Description: Touches filesystem paths that only exist on QEMU/emulator images.

**🟡 MEDIUM** `anti-emulator-build-fingerprint`
: Build.FINGERPRINT substring check

- Evidence: `DEX string match: `
Use 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys.
JSON input: `, ` failed because of an unknown error`, ` has unkno…`
- Description: Checks Build.FINGERPRINT/MODEL/PRODUCT for emulator markers.

**🟡 MEDIUM** `anti-emulator-network`
: Emulator network probe

- Evidence: `DEX string match: `/sys/class/net/eth0/address``
- Description: Checks IP/iface for default emulator networking.

**🟡 MEDIUM** `anti-emulator-sensors`
: Sensor / hardware presence check

- Evidence: `DEX string match: `Landroid/hardware/SensorManager;`, `mSensorManager`, `null cannot be cast to non-null type android.hardware.SensorManager``
- Description: Checks for absence of expected hardware sensors (weak signal alone).

**🟡 MEDIUM** `anti-emulator-telephony`
: Telephony emulator markers

- Evidence: `DEX string match: `Landroid/telephony/HwTelephonyManager;`, `Landroid/telephony/TelephonyManager$CellInfoCallback;`, `Landroid/telephony/TelephonyManager;``
- Description: Probes TelephonyManager — emulator returns well-known dummy values.

### Clone / Repackage (1 finding)

**🟡 MEDIUM** `clone-installer-source`
: Installer source check

- Evidence: `DEX string match: `getInstallerPackageName``
- Description: Checks which app store installed the APK — used to reject sideloaded clones.

