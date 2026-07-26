package id.zai.apkdetector.data

/**
 * Native bridge to the Rust `jni-bridge` crate.
 *
 * Loads `libapk_detector.so` on first access and exposes the six JNI exports
 * as idiomatic Kotlin functions. Errors from the Rust side arrive as
 * `{"error": "..."}` JSON; we parse them and surface them via [ScanResult.Err].
 *
 * ## JNI exports
 *
 * 1. `scanApk(path)` — full Markdown report (all severities)
 * 2. `diffApks(oldPath, newPath)` — Markdown diff of two APK versions
 * 3. `listSignatures()` — JSON array of built-in rule metadata
 * 4. `engineVersion()` — semver + git SHA
 * 5. `scanApkBlockingOnly(path)` — Markdown report filtered to Medium / High /
 *    Critical severity findings only (block/restrict filter). Low and Info
 *    findings are hidden — useful for answering "which defenses in this APK
 *    will actually stop a real user?".
 * 6. `scanApkSimulated(path, profileJson)` — runs the scan, then evaluates
 *    each finding against the supplied [DeviceProfile] JSON and emits a
 *    simulation report showing which detections would TRIGGER on the device
 *    vs BYPASS vs UNKNOWN. Use [DeviceProfile.presets] for curated profiles.
 * 7. `scanDevice(profileJson)` — evaluates the device-detection verdict
 *    table against the LIVE device's state (described by [profileJson])
 *    WITHOUT requiring an APK. Use [DeviceProbe.gather] to build the
 *    profile from real Android APIs (Build, Settings, PackageManager, etc.),
 *    then pass it to [NativeBridge.deviceScan]. Returns a Markdown "device
 *    self-scan" report showing which detections would fire on this device.
 *
 * ## Threading
 *
 * All native methods are SYNCHRONOUS and BLOCKING. Callers MUST run them on
 * a worker thread (e.g. `withContext(Dispatchers.IO)`) — calling them on
 * the main thread will freeze the UI for the duration of the scan.
 */
object NativeBridge {
    init {
        System.loadLibrary("apk_detector")
    }

    private external fun scanApk(path: String): String
    private external fun diffApks(oldPath: String, newPath: String): String
    private external fun listSignatures(): String
    private external fun engineVersion(): String
    private external fun scanApkBlockingOnly(path: String): String
    private external fun scanApkSimulated(path: String, profileJson: String): String
    private external fun scanDevice(profileJson: String): String

    /** Run a static scan on a single APK file. Returns full Markdown report. */
    fun scan(path: String): ScanResult {
        val raw = scanApk(path)
        return ScanResult.parse(raw)
    }

    /**
     * Run a static scan and return a FILTERED Markdown report containing only
     * findings whose severity would block or restrict the user (Medium / High /
     * Critical). Low and Info findings are hidden — use [scan] for the full
     * picture.
     */
    fun scanBlockingOnly(path: String): ScanResult {
        val raw = scanApkBlockingOnly(path)
        return ScanResult.parse(raw)
    }

    /**
     * Run a static scan, then simulate which findings would TRIGGER on a
     * device matching [profileJson]. Returns a Markdown simulation report
     * with three sections: 🔴 Triggered, 🟢 Bypassed, ⚪ Unknown.
     *
     * The [profileJson] must be a JSON object whose keys match the
     * [DeviceProfile] schema. See [DeviceProfile.presets] for curated
     * examples.
     */
    fun scanSimulated(path: String, profileJson: String): ScanResult {
        val raw = scanApkSimulated(path, profileJson)
        return ScanResult.parse(raw)
    }

    /**
     * Evaluate the device-detection verdict table against the LIVE device
     * described by [profileJson] WITHOUT requiring an APK. The profile is
     * typically built by [DeviceProbe.gather] from real Android APIs.
     *
     * Returns a Markdown "device self-scan" report showing which detections
     * would fire on this device. Same format as [scanSimulated] but with
     * device-scan wording.
     *
     * Naming note: the underlying JNI export is `scanDevice` (matches the
     * Rust `Java_..._NativeBridge_scanDevice` symbol). The Kotlin public
     * wrapper is `deviceScan` to avoid the recursive self-call that would
     * happen if both shared the name `scanDevice`.
     */
    fun deviceScan(profileJson: String): ScanResult {
        val raw = scanDevice(profileJson)
        return ScanResult.parse(raw)
    }

    /** Diff two APK versions. Returns Markdown diff report. */
    fun diff(oldPath: String, newPath: String): ScanResult {
        val raw = diffApks(oldPath, newPath)
        return ScanResult.parse(raw)
    }

    /** List all built-in detection rules as JSON. */
    fun signatures(): String = listSignatures()

    /** Engine semver, e.g. "0.1.0+e5114a4". */
    fun version(): String = engineVersion()
}

/**
 * Curated device profiles for [NativeBridge.scanSimulated]. Each preset is a
 * JSON string ready to pass as `profileJson`.
 *
 * Presets:
 * - `"clean"` — stock Android, no root, Play Integrity passing, Play Store installer.
 * - `"rooted-magisk"` — rooted with Magisk DenyList ON + Play Integrity Fix.
 * - `"rooted-no-magisk"` — rooted via KingRoot/etc. with no stealth.
 * - `"emulator"` — Android Studio emulator.
 * - `"frida"` — Frida server running.
 * - `"dev-options-on"` — Developer Options + USB debugging enabled.
 */
object DeviceProfile {
    val presets: Map<String, String> = mapOf(
        "clean" to """{"rooted":false,"magisk_denylist_on":false,"play_integrity_passes":true,"safetynet_passes":true,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":false,"developer_options_on":false,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
        "rooted-magisk" to """{"rooted":true,"magisk_denylist_on":true,"play_integrity_passes":true,"safetynet_passes":true,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":false,"developer_options_on":false,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
        "rooted-no-magisk" to """{"rooted":true,"magisk_denylist_on":false,"play_integrity_passes":false,"safetynet_passes":false,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":false,"developer_options_on":false,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
        "emulator" to """{"rooted":false,"magisk_denylist_on":false,"play_integrity_passes":false,"safetynet_passes":false,"installer_is_play_store":false,"in_clone_runtime":false,"is_emulator":true,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":true,"developer_options_on":true,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
        "frida" to """{"rooted":false,"magisk_denylist_on":false,"play_integrity_passes":true,"safetynet_passes":true,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":true,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":false,"developer_options_on":false,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
        "dev-options-on" to """{"rooted":false,"magisk_denylist_on":false,"play_integrity_passes":true,"safetynet_passes":true,"installer_is_play_store":true,"in_clone_runtime":false,"is_emulator":false,"frida_running":false,"xposed_loaded":false,"mock_location_on":false,"vpn_active":false,"debugger_attached":true,"developer_options_on":true,"accessibility_service_on":false,"media_projection_active":false,"play_services_available":true,"is_samsung_knox":false,"widevine_l1":false,"repackaged":false,"self_integrity_broken":false}""",
    )
}

/**
 * In-memory cache mapping APK path → Markdown report.
 *
 * ## Why this exists
 *
 * `ScanProgressScreen` runs the scan, then navigates to `ReportScreen`. The
 * naive way to pass the result is via a nav-route argument, but Markdown
 * reports can exceed the Android Bundle size cap (~1 MB after URL-encoding)
 * and contain `%` characters that trigger `IllegalArgumentException` in
 * Navigation Compose's `Uri.decode()` (see IMPL-001 crash fix in
 * `AppNavGraph.kt`).
 *
 * Instead, `ScanProgressScreen` writes the Markdown to this cache keyed by
 * the APK path, then navigates with only the (short, URL-safe) path.
 * `ReportScreen` reads the Markdown back from the cache. On cache miss
 * (process death, deep-link, etc.) `ReportScreen` falls back to a fresh
 * `NativeBridge.scan(apkPath)` call.
 *
 * ## Lifecycle
 *
 * Process-scoped (object singleton). Cleared automatically on process
 * death. No eviction policy needed — typical usage is one entry at a time.
 * `clear()` is provided for explicit cleanup (e.g., a future "clear cache"
 * button).
 */
object ScanResultCache {
    private val map = mutableMapOf<String, String>()

    fun put(apkPath: String, markdown: String) {
        map[apkPath] = markdown
    }

    fun get(apkPath: String): String? = map[apkPath]

    fun clear() {
        map.clear()
    }
}

/** Either a successful scan's Markdown output, or an error message. */
sealed class ScanResult {
    data class Ok(val markdown: String) : ScanResult()
    data class Err(val message: String) : ScanResult()

    companion object {
        fun parse(raw: String): ScanResult {
            // The Rust side wraps errors as `{"error": "..."}` JSON.
            // Cheap check first to avoid pulling a JSON parser.
            val trimmed = raw.trimStart()
            if (trimmed.startsWith("{\"error\"")) {
                // Extract "error":"..."  via a simple regex-free scan
                val key = "\"error\":\""
                val start = trimmed.indexOf(key)
                if (start < 0) return Err(raw)
                val s = start + key.length
                val sb = StringBuilder()
                var i = s
                while (i < trimmed.length) {
                    val c = trimmed[i]
                    if (c == '\\' && i + 1 < trimmed.length) {
                        when (val n = trimmed[i + 1]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\')
                            'n' -> sb.append('\n'); 'r' -> sb.append('\r')
                            't' -> sb.append('\t'); else -> sb.append(n)
                        }
                        i += 2; continue
                    }
                    if (c == '"') break
                    sb.append(c); i += 1
                }
                return Err(sb.toString())
            }
            return Ok(raw)
        }
    }
}
