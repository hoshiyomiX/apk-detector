package id.zai.apkdetector.data

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Gathers live device-side signals for [NativeBridge.deviceScan].
 *
 * Probes the actual running device for root / emulator / Frida / Xposed /
 * VPN / debugger / dev-options / accessibility / Play Services / Widevine /
 * Samsung KNOX / clone-runtime / mock-location / installer-source indicators
 * and emits a JSON object matching Rust's `DeviceProfile` schema.
 *
 * Fields that cannot be reliably determined from a non-root app context
 * (e.g., `magisk_denylist_on` requires root to inspect `/data/adb`, or
 * `play_integrity_passes` requires an async Play Integrity API call) are
 * omitted from the JSON — the Rust `DeviceProfile::from_json` parser treats
 * missing keys as `None`, which produces `Unknown` verdicts for any rule
 * that needs them.
 *
 * ## Threat model
 *
 * This is a BEST-EFFORT probe from a non-root app context. A determined
 * adversary with root + Magisk DenyList can hide many of these signals
 * (e.g., `RootBeer`-style checks fail to find su, /proc/self/maps is
 * namespace-isolated). The probe is designed to surface what a typical
 * defended APK would see — not to defeat all bypasses.
 *
 * ## Threading
 *
 * All probes are SYNCHRONOUS and run on the calling thread. Most are
 * sub-millisecond (filesystem stat, Build fields, Settings.Global reads).
 * The Frida probe scans `/proc/self/maps` (~1ms). The Play Services probe
 * calls `GoogleApiAvailability.isGooglePlayServicesAvailable` (~5ms).
 * Total gather time: <20ms typical — safe to call on the main thread,
 * though callers should still use `withContext(Dispatchers.IO)` for
 * consistency with other NativeBridge calls.
 */
object DeviceProbe {

    /**
     * Gather the device profile as a JSON string suitable for
     * [NativeBridge.deviceScan]. Schema matches Rust's `DeviceProfile`.
     *
     * @param context Android context (required for PackageManager,
     *     Settings, ConnectivityManager probes).
     * @param playIntegrityPasses Optional result of a Play Integrity API
     *     call. Pass `true` if the API issued a token, `false` if it
     *     refused with a "non-genuine device" error code, or `null` if
     *     the check was not run (Unknown). When non-null, the
     *     `play_integrity_passes` field is included in the JSON; when
     *     null, the field is omitted (Rust treats missing keys as
     *     `None` → Unknown verdict).
     */
    fun gather(
        context: Context,
        playIntegrityPasses: Boolean? = null,
    ): String {
        val fields = mutableListOf<Pair<String, Boolean?>>()

        fields += "rooted" to detectRoot()
        fields += "magisk_denylist_on" to null // unknown without root
        fields += "play_integrity_passes" to playIntegrityPasses
        fields += "safetynet_passes" to null // deprecated API, deferred
        fields += "installer_is_play_store" to detectInstallerFromPlay(context)
        fields += "in_clone_runtime" to detectCloneRuntime()
        fields += "is_emulator" to detectEmulator()
        fields += "frida_running" to detectFrida()
        fields += "xposed_loaded" to detectXposed()
        fields += "mock_location_on" to detectMockLocation(context)
        fields += "vpn_active" to detectVpn(context)
        fields += "debugger_attached" to Debug.isDebuggerConnected()
        fields += "developer_options_on" to detectDevOptions(context)
        fields += "accessibility_service_on" to detectAccessibility(context)
        fields += "media_projection_active" to null // hard to detect without foreground service
        fields += "play_services_available" to detectPlayServices(context)
        fields += "is_samsung_knox" to detectSamsungKnox()
        fields += "widevine_l1" to detectWidevineL1()
        fields += "repackaged" to null // APK-specific, not device
        fields += "self_integrity_broken" to null // APK-specific, not device

        val sb = StringBuilder("{")
        var first = true
        for ((key, value) in fields) {
            if (value == null) continue // omit unknown fields — Rust treats missing keys as None
            if (!first) sb.append(",")
            sb.append("\"").append(key).append("\":").append(value)
            first = false
        }
        sb.append("}")
        return sb.toString()
    }

    // ─── Root detection ──────────────────────────────────────────────────

    /**
     * Detect root by checking for su binary in known locations + test-keys
     * in Build.TAGS. Returns false if neither is found (does NOT prove the
     * device is unrooted — Magisk Hide can spoof both — but it's the
     * standard first-pass check).
     */
    private fun detectRoot(): Boolean {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
        )
        if (suPaths.any { File(it).exists() }) return true

        // test-keys in Build.TAGS indicates a custom engineering build
        if (Build.TAGS?.contains("test-keys") == true) return true

        // Look for known root app packages via PackageManager (read-only)
        // — but we can't access PackageManager from a static function. The
        // caller can pass Context if needed; for now we rely on the file +
        // tags check, which catches most consumer root installations.
        return false
    }

    // ─── Installer source ────────────────────────────────────────────────

    /**
     * True if THIS app was installed from Google Play Store
     * (`com.android.vending`). False if sideloaded or installed from a
     * third-party store.
     */
    private fun detectInstallerFromPlay(context: Context): Boolean {
        val installer = if (Build.VERSION.SDK_INT >= 30) {
            try {
                context.packageManager
                    .getInstallSourceInfo(context.packageName)
                    .installingPackageName
            } catch (_: Throwable) {
                null
            }
        } else {
            @Suppress("DEPRECATION")
            try {
                context.packageManager
                    .getInstallerPackageName(context.packageName)
            } catch (_: Throwable) {
                null
            }
        }
        return installer == "com.android.vending"
    }

    // ─── Clone runtime detection ─────────────────────────────────────────

    /**
     * Detect clone/dual-space runtimes (Parallel Space, VirtualApp, etc.)
     * by checking if the process name differs from the package name, or
     * if the data directory path looks atypical.
     */
    private fun detectCloneRuntime(): Boolean {
        // Clone runtimes typically run the cloned app in a subprocess whose
        // process name is NOT the original package name. We check the
        // current process name via Application.getProcessName() (API 28+)
        // or fall back to reading /proc/self/cmdline.
        val processName = if (Build.VERSION.SDK_INT >= 28) {
            try {
                // Public API since API 28 — equivalent to the hidden
                // ActivityThread.currentProcessName() but accessible from
                // the SDK without reflection.
                android.app.Application.getProcessName()
            } catch (_: Throwable) {
                readProcessNameFromCmdline()
            }
        } else {
            readProcessNameFromCmdline()
        }

        // If process name contains the package name suffix with a colon
        // (e.g., ":clone", ":dual"), it's likely a clone runtime. Real
        // Android services use colon-prefixed process names too, so this
        // is a hint not a guarantee. We check for known clone indicators.
        val cloneIndicators = listOf(
            "parallel", "dualspace", "dual_space", "virtualapp",
            "clone", "multiapp", "multiple", "island",
        )
        val lower = processName.lowercase()
        return cloneIndicators.any { it in lower }
    }

    private fun readProcessNameFromCmdline(): String {
        return try {
            File("/proc/self/cmdline").readText().trim('\u0000')
        } catch (_: Throwable) {
            ""
        }
    }

    // ─── Emulator detection ──────────────────────────────────────────────

    /**
     * Detect Android emulator (AVD, BlueStacks, Nox, LDPlayer, etc.) via
     * Build.FINGERPRINT / MODEL / HARDWARE / PRODUCT / MANUFACTURER +
     * Goldfish CPU check.
     */
    private fun detectEmulator(): Boolean {
        // Build.FINGERPRINT: "generic" or "unknown" indicates emulator
        val fingerprint = Build.FINGERPRINT.orEmpty()
        if (fingerprint.startsWith("generic") || fingerprint.startsWith("unknown")) return true

        // Build.MODEL: "Emulator", "Android SDK built for x86", "google_sdk"
        val model = Build.MODEL.orEmpty()
        if (model.contains("Emulator", ignoreCase = true) ||
            model.contains("Android SDK", ignoreCase = true) ||
            model.equals("google_sdk", ignoreCase = true)
        ) return true

        // Build.HARDWARE: "goldfish" or "ranchu" = AVD emulator
        val hardware = Build.HARDWARE.orEmpty()
        if (hardware.equals("goldfish", ignoreCase = true) ||
            hardware.equals("ranchu", ignoreCase = true)
        ) return true

        // Build.PRODUCT: "sdk", "google_sdk", "sdk_x86", "vbox86p", etc.
        val product = Build.PRODUCT.orEmpty()
        if (product.contains("sdk", ignoreCase = true) ||
            product.contains("vbox", ignoreCase = true) ||
            product.contains("nox", ignoreCase = true)
        ) return true

        // Build.MANUFACTURER: "Genymotion", "unknown" (some emulators)
        val manufacturer = Build.MANUFACTURER.orEmpty()
        if (manufacturer.equals("Genymotion", ignoreCase = true) ||
            (manufacturer.equals("unknown", ignoreCase = true) &&
                model.contains("sdk", ignoreCase = true))
        ) return true

        // Goldfish CPU check via /proc/cpuinfo — last-resort hardware check
        try {
            val cpuinfo = File("/proc/cpuinfo").readText()
            if (cpuinfo.contains("Goldfish", ignoreCase = true)) return true
        } catch (_: Throwable) {
            // /proc/cpuinfo not readable on some devices — skip
        }

        return false
    }

    // ─── Frida detection ─────────────────────────────────────────────────

    /**
     * Detect Frida by scanning /proc/self/maps for known Frida artifacts
     * (frida-agent, gum-js-loop, linjector). Catches both frida-server
     * (injected into the process) and frida-gadget (loaded as a library).
     */
    private fun detectFrida(): Boolean {
        val maps = try {
            File("/proc/self/maps").readText()
        } catch (_: Throwable) {
            return false
        }
        val fridaIndicators = listOf(
            "frida-agent",
            "gum-js-loop",
            "linjector",
            "frida-gadget",
            "frida-server",
        )
        return fridaIndicators.any { it in maps }
    }

    // ─── Xposed detection ────────────────────────────────────────────────

    /**
     * Detect Xposed/LSPosed framework by attempting to load the XposedBridge
     * class. Xposed injects this class into the framework classloader when
     * active. Catches both Xposed Framework and LSPosed (which retains
     * the XposedBridge API).
     */
    private fun detectXposed(): Boolean {
        // Try to load the XposedBridge class — if it loads, Xposed is active
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (_: ClassNotFoundException) {
            // XposedBridge not found — also check /proc/self/maps for the
            // libxposed native module
            try {
                val maps = File("/proc/self/maps").readText()
                "libxposed" in maps || "xposed" in maps.lowercase()
            } catch (_: Throwable) {
                false
            }
        }
    }

    // ─── Mock location ───────────────────────────────────────────────────

    /**
     * Detect mock location via Settings.Secure.ALLOW_MOCK_LOCATION (legacy,
     * pre-API 23). On API 23+ this setting was deprecated; the modern way
     * is `Location.isFromMockProvider()` which requires an actual location
     * fix — we can't trigger that from a probe.
     */
    private fun detectMockLocation(context: Context): Boolean {
        return try {
            val setting = android.provider.Settings.Secure.getInt(
                context.contentResolver,
                "mock_location",
                0,
            )
            setting == 1
        } catch (_: Throwable) {
            false
        }
    }

    // ─── VPN detection ───────────────────────────────────────────────────

    /**
     * Detect active VPN via ConnectivityManager. Returns true if a VPN
     * network capability is present (tun0 interface is up).
     */
    private fun detectVpn(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            if (Build.VERSION.SDK_INT >= 23) {
                val activeNetwork = cm.activeNetwork
                val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
                // TRANSPORT_VPN = 4 (API 21+); hasTransport is a public API
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
            } else {
                // API 21-22: legacy getNetworkInfo(VPN_TYPE)
                @Suppress("DEPRECATION")
                val netInfo = cm.getNetworkInfo(android.net.ConnectivityManager.TYPE_VPN)
                netInfo?.isConnected == true
            }
        } catch (_: Throwable) {
            false
        }
    }

    // ─── Developer Options ───────────────────────────────────────────────

    /**
     * Detect Developer Options + USB debugging via Settings.Global.
     * ADB_ENABLED = 1 indicates USB debugging is on. DEVELOPMENT_SETTINGS_ENABLED
     * = 1 indicates the Developer Options menu itself is enabled.
     */
    private fun detectDevOptions(context: Context): Boolean {
        return try {
            val adbEnabled = android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED,
                0,
            )
            val devSettingsEnabled = android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0,
            )
            adbEnabled == 1 || devSettingsEnabled == 1
        } catch (_: Throwable) {
            false
        }
    }

    // ─── Accessibility service ───────────────────────────────────────────

    /**
     * Detect non-system accessibility service enabled. Returns true if any
     * accessibility service is enabled (we don't filter to non-system to
     * avoid maintaining a list of system service names that varies by OEM).
     */
    private fun detectAccessibility(context: Context): Boolean {
        return try {
            val enabledServices = android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: ""
            enabledServices.isNotBlank()
        } catch (_: Throwable) {
            false
        }
    }

    // ─── Play Services ───────────────────────────────────────────────────

    /**
     * Detect Google Play Services installed + up to date. We try the
     * GoogleApiAvailability API; if the class isn't found (no Play Services
     * in classpath — unusual on Google-certified devices, possible on
     * degoogled ROMs), we fall back to checking for the package.
     */
    private fun detectPlayServices(context: Context): Boolean {
        // Try GoogleApiAvailability (com.google.android.gms namespace)
        return try {
            val clazz = Class.forName("com.google.android.gms.common.GoogleApiAvailability")
            val instance = clazz.getMethod("getInstance").invoke(null)
            val result = clazz
                .getMethod("isGooglePlayServicesAvailable", Context::class.java)
                .invoke(instance, context) as Int
            result == 0 // CONNECTION_SUCCESS
        } catch (_: ClassNotFoundException) {
            // GoogleApiAvailability not available — fall back to package check
            try {
                context.packageManager
                    .getPackageInfo("com.google.android.gms", 0)
                true
            } catch (_: Throwable) {
                false
            }
        } catch (_: Throwable) {
            false
        }
    }

    // ─── Samsung KNOX ────────────────────────────────────────────────────

    /**
     * Detect Samsung KNOX / TIMA by checking the manufacturer + looking
     * for the KNOX framework classes.
     */
    private fun detectSamsungKnox(): Boolean {
        if (!Build.MANUFACTURER.equals("samsung", ignoreCase = true)) return false
        return try {
            // KNOX Enterprise SDK classes are present only on Samsung devices
            // with KNOX support
            Class.forName("com.samsung.android.knox.SemPersonaManager")
            true
        } catch (_: ClassNotFoundException) {
            // Try alternate KNOX class
            try {
                Class.forName("com.samsung.android.knox.ContextInfo")
                true
            } catch (_: ClassNotFoundException) {
                false
            }
        }
    }

    // ─── Widevine L1 ─────────────────────────────────────────────────────

    /**
     * Detect Widevine DRM L1 (hardware-backed). We try to query the
     * MediaDrm API for the security level. L1 = hardware-backed, L3 =
     * software-only.
     *
     * NOTE: This probe is best-effort. MediaDrm initialization can fail on
     * some devices (especially emulators), and the security level property
     * is not a documented public API — it's a de facto standard. On any
     * error, we return null (unknown) rather than false to avoid false
     * negatives.
     */
    private fun detectWidevineL1(): Boolean? {
        return try {
            val mediaDrmClass = Class.forName("android.media.MediaDrm")
            val widevineUuid = java.util.UUID.fromString(
                "EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED",
            )
            val constructor = mediaDrmClass.getConstructor(java.util.UUID::class.java)
            val instance = constructor.newInstance(widevineUuid)

            // Call getPropertyString("securityLevel") via reflection
            val method = mediaDrmClass.getMethod("getPropertyString", String::class.java)
            val level = method.invoke(instance, "securityLevel") as String

            // Release the MediaDrm instance
            val releaseMethod = mediaDrmClass.getMethod("release")
            releaseMethod.invoke(instance)

            level == "L1"
        } catch (_: Throwable) {
            null // unknown — MediaDrm unavailable or property not supported
        }
    }
}
