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
            is ApkSource.Uri -> copyUriToCacheExt(context, source.uri, "scan")
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
