package id.zai.apkdetector.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File

/**
 * Repository: high-level scan operations + history persistence.
 *
 * The Rust side accepts only filesystem paths — no file descriptors, no
 * Content URIs. This layer bridges SAF URIs to real file paths by copying
 * the picked file into the app's cache directory before scanning.
 */
class Repository(private val dao: ScanDao) {

    /**
     * Scan an APK identified by either:
     *  - a real filesystem path (legacy storage API)
     *  - a content:// URI from SAF
     * Returns the Markdown report. Persists a history entry on success.
     */
    suspend fun scan(context: Context, source: ApkSource): ScanResult {
        val path = when (source) {
            is ApkSource.Path -> source.path
            is ApkSource.Uri -> copyUriToCacheExt(context, source.uri, "scan")?.absolutePath
        } ?: return ScanResult.Err("Could not resolve APK path from $source")

        val result = try {
            NativeBridge.scan(path)
        } catch (t: Throwable) {
            ScanResult.Err("Native scan threw: ${t.message}")
        }

        if (result is ScanResult.Ok) {
            dao.insert(ScanEntity(
                apkLabel = source.label,
                apkPath = path,
                markdown = result.markdown,
                createdAt = System.currentTimeMillis(),
            ))
        }
        return result
    }

    /**
     * AUTO-CHAIN scan — runs the APK scan AND the blocking-only device
     * simulation in one call, populating both [ScanResultCache] and
     * [SimulationResultCache] so [ReportScreen] can render both sections
     * without re-running either.
     *
     * ## Chain (verbatim from user's requested flow)
     *
     *   1. **scan apk target** — `NativeBridge.scan(path)` produces the
     *      full Markdown report. Persisted to history (same as [scan]).
     *   2. **data result 'blocking-only filter' diperoleh** — applied
     *      inside Rust's `simulate_blocking_only` (filters findings to
     *      `behavior.is_user_blocking()`).
     *   3. **auto-call Play Integrity** — `PlayIntegrityClient.requestVerdict`
     *      runs asynchronously. If the cloud project number is not
     *      configured (`Result.NotConfigured`) or the API errors out
     *      (`Result.Error`), `play_integrity_passes` is left null and
     *      the Rust verdict table returns `Unknown` for any rule that
     *      needs it. This is non-fatal — the simulation still runs.
     *   4. **gather live device profile** — `DeviceProbe.gather` collects
     *      ~14 device signals (root, emulator, Frida, Xposed, VPN,
     *      debugger, dev-options, etc.) into a JSON profile.
     *   5. **auto simulasi sesuai data result** —
     *      `NativeBridge.scanSimulatedBlocking(path, profileJson)` runs
     *      the verdict table over the filtered set against the live
     *      device profile. Returns Markdown with an "Overall Verdict"
     *      banner (PASS / FAIL / INCONCLUSIVE / NO BLOCKING DETECTIONS).
     *   6. **rangkuman hasil test** — the Overall Verdict banner IS
     *      the summary, embedded in the simulation Markdown. The caller
     *      (ScanProgressScreen) navigates to ReportScreen which renders
     *      both Markdown blocks.
     *
     * ## Failure semantics
     *
     * - If the APK scan fails → return `ScanResult.Err` immediately,
     *   no simulation is attempted, no history row is inserted.
     * - If Play Integrity fails → simulation runs with
     *   `play_integrity_passes = null` (Unknown verdict for PI rules).
     *   The simulation Markdown surfaces this as a "⚪ Unknown" entry
     *   with a note suggesting the user manually verify.
     * - If the simulation itself fails → the APK scan Markdown is
     *   still cached + history still inserted; the simulation error
     *   is cached as a small error Markdown block so ReportScreen can
     *   display it inline.
     *
     * ## Threading
     *
     * All steps run on `Dispatchers.IO` (caller is responsible for
     * switching off the main thread — typically via `withContext`).
     * The Play Integrity call has a 15s warm-up + 10s token request
     * timeout, so total chain time can be up to 30s on a cold device.
     *
     * @return the APK scan result (same shape as [scan]). The simulation
     *   result is delivered via [SimulationResultCache] — callers should
     *   read it from there, NOT from the return value.
     */
    suspend fun scanWithAutoSimulation(
        context: Context,
        source: ApkSource,
    ): ScanResult {
        val path = when (source) {
            is ApkSource.Path -> source.path
            is ApkSource.Uri -> copyUriToCacheExt(context, source.uri, "scan")?.absolutePath
        } ?: return ScanResult.Err("Could not resolve APK path from $source")

        // Step 1: scan APK
        val scanResult = try {
            NativeBridge.scan(path)
        } catch (t: Throwable) {
            ScanResult.Err("Native scan threw: ${t.message}")
        }

        if (scanResult is ScanResult.Err) return scanResult

        val scanMarkdown = (scanResult as ScanResult.Ok).markdown
        ScanResultCache.put(path, scanMarkdown)
        dao.insert(ScanEntity(
            apkLabel = source.label,
            apkPath = path,
            markdown = scanMarkdown,
            createdAt = System.currentTimeMillis(),
        ))

        // Steps 2-5: blocking-only simulation chained with Play Integrity +
        // device probe. Failures here are non-fatal — we cache an error
        // Markdown so ReportScreen can show it inline, but the scan itself
        // succeeded.
        val simMarkdown = try {
            // Step 3: auto-call Play Integrity (non-fatal on failure).
            val playIntegrityPasses: Boolean? = try {
                when (val piResult = PlayIntegrityClient.requestVerdict(context)) {
                    is PlayIntegrityClient.Result.Passes -> piResult.value
                    PlayIntegrityClient.Result.NotConfigured -> null
                    is PlayIntegrityClient.Result.Error -> null
                }
            } catch (_: Throwable) {
                null
            }

            // Step 4: gather live device profile with the PI verdict baked in.
            val profileJson = DeviceProbe.gather(
                context = context,
                playIntegrityPasses = playIntegrityPasses,
            )

            // Steps 2 + 5: blocking-only filter + verdict table run on the
            // filtered set, against the live device profile.
            when (val simResult = NativeBridge.scanSimulatedBlocking(path, profileJson)) {
                is ScanResult.Ok -> simResult.markdown
                is ScanResult.Err -> buildSimErrorMarkdown(simResult.message)
            }
        } catch (t: Throwable) {
            buildSimErrorMarkdown("Native simulation threw: ${t.message}")
        }

        SimulationResultCache.put(path, simMarkdown)
        return scanResult
    }

    /**
     * Build a minimal Markdown block that ReportScreen can render inline
     * when the simulation step fails. Mirrors the "Overall Verdict"
     * banner shape so the UI's verdict parser stays simple.
     */
    private fun buildSimErrorMarkdown(message: String): String = buildString {
        appendLine("# APK Detector — Blocking-Only Device Simulation")
        appendLine()
        appendLine("**Engine:** APK Detector (simulation failed)")
        appendLine()
        appendLine("## Overall Verdict")
        appendLine()
        appendLine("**⚠ SIMULATION ERROR — the APK scan succeeded but the device simulation step could not complete.**")
        appendLine()
        appendLine("Error: `$message`")
        appendLine()
        appendLine("The scan report above is still valid — only the simulation step failed. " +
            "You can re-run the simulation manually from the home screen's \"Scan this device\" " +
            "button.")
    }

    /** Diff two APK versions. No history persistence (diffs are ad-hoc). */
    suspend fun diff(context: Context, oldSrc: ApkSource, newSrc: ApkSource): ScanResult {
        val oldPath = resolve(context, oldSrc) ?: return ScanResult.Err("Could not open old APK")
        val newPath = resolve(context, newSrc) ?: return ScanResult.Err("Could not open new APK")
        return try {
            NativeBridge.diff(oldPath, newPath)
        } catch (t: Throwable) {
            ScanResult.Err("Native diff threw: ${t.message}")
        }
    }

    suspend fun history(): List<ScanEntity> = dao.getAll()

    suspend fun clearHistory() = dao.deleteAll()

    private suspend fun resolve(context: Context, source: ApkSource): String? = when (source) {
        is ApkSource.Path -> source.path
        is ApkSource.Uri -> copyUriToCacheExt(context, source.uri, "diff")?.absolutePath
    }
}

/**
 * Copy a content URI to a cache file, preserving the source extension.
 *
 * The Rust `open_any` dispatcher detects `.apks` containers by extension,
 * so we MUST preserve the original extension (`.apk` or `.apks`) in the
 * cache filename. A `.apks` saved as `picked_*.apk` would be parsed as a
 * regular APK and fail with "bad CDH" or similar.
 *
 * Extension detection:
 *  1. Query `OpenableColumns.DISPLAY_NAME` from the content resolver.
 *  2. Extract the substring after the last `.`.
 *  3. Sanitize: only allow alphanumeric, length 1–8 (covers `apk`, `apks`,
 *     `xapk`, `zip`; rejects anything weird).
 *  4. Default to `apk` if any step fails.
 *
 * Returns the cache File on success, or null on any I/O or query error.
 */
fun copyUriToCacheExt(context: Context, uri: Uri, prefix: String): File? {
    return try {
        val ext = queryDisplayName(context, uri)
            ?.substringAfterLast('.', missingDelimiterValue = "")
            ?.lowercase()
            ?.takeIf { it.isNotEmpty() && it.length <= 8 && it.all { c -> c.isLetterOrDigit() } }
            ?: "apk"
        val cacheFile = File(context.cacheDir, "${prefix}_${System.currentTimeMillis()}.$ext")
        context.contentResolver.openInputStream(uri)?.use { input ->
            cacheFile.outputStream().use { out -> input.copyTo(out) }
        } ?: return null
        cacheFile
    } catch (_: Throwable) {
        null
    }
}

private fun queryDisplayName(context: Context, uri: Uri): String? {
    return try {
        context.contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
    } catch (_: Throwable) {
        null
    }
}

/** Source of an APK to scan. Either a raw filesystem path or a SAF content URI. */
sealed class ApkSource {
    abstract val label: String
    data class Path(val path: String, override val label: String) : ApkSource()
    data class Uri(val uri: android.net.Uri, override val label: String) : ApkSource()
}
