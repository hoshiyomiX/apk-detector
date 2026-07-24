package id.zai.apkdetector.data

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.io.FileOutputStream

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
            is ApkSource.Uri -> copyUriToCache(context, source.uri)
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
        is ApkSource.Uri -> copyUriToCache(context, source.uri)
    }

    private fun copyUriToCache(context: Context, uri: Uri): String? {
        return try {
            val input = context.contentResolver.openInputStream(uri) ?: return null
            val cacheFile = File(context.cacheDir, "scan_${System.currentTimeMillis()}.apk")
            FileOutputStream(cacheFile).use { out -> input.copyTo(out) }
            input.close()
            cacheFile.absolutePath
        } catch (t: Throwable) {
            null
        }
    }
}

/** Source of an APK to scan. Either a raw filesystem path or a SAF content URI. */
sealed class ApkSource {
    abstract val label: String
    data class Path(val path: String, override val label: String) : ApkSource()
    data class Uri(val uri: android.net.Uri, override val label: String) : ApkSource()
}
