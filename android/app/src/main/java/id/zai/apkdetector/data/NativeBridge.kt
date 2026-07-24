package id.zai.apkdetector.data

/**
 * Native bridge to the Rust `jni-bridge` crate.
 *
 * Loads `libapk_detector.so` on first access and exposes the four JNI exports
 * as idiomatic Kotlin suspend-or-blocking functions. Errors from the Rust side
 * arrive as `{"error": "..."}` JSON; we parse them and throw [ScanException].
 */
object NativeBridge {
    init {
        System.loadLibrary("apk_detector")
    }

    private external fun scanApk(path: String): String
    private external fun diffApks(oldPath: String, newPath: String): String
    private external fun listSignatures(): String
    private external fun engineVersion(): String

    /** Run a static scan on a single APK file. Returns Markdown report. */
    fun scan(path: String): ScanResult {
        val raw = scanApk(path)
        return ScanResult.parse(raw)
    }

    /** Diff two APK versions. Returns Markdown diff report. */
    fun diff(oldPath: String, newPath: String): ScanResult {
        val raw = diffApks(oldPath, newPath)
        return ScanResult.parse(raw)
    }

    /** List all built-in detection rules as JSON. */
    fun signatures(): String = listSignatures()

    /** Engine semver, e.g. "0.1.0". */
    fun version(): String = engineVersion()
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
