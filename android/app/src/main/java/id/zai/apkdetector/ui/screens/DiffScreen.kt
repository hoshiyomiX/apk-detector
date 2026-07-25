package id.zai.apkdetector.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.ApkDetectorApp
import id.zai.apkdetector.data.ApkSource
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.data.copyUriToCacheExt
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiffScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val repo = remember { ApkDetectorApp.get().repository }
    val scope = rememberCoroutineScope()

    var oldPath by remember { mutableStateOf<String?>(null) }
    var newPath by remember { mutableStateOf<String?>(null) }
    var oldLabel by remember { mutableStateOf("old APK") }
    var newLabel by remember { mutableStateOf("new APK") }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    var busy by remember { mutableStateOf(false) }
    var copying by remember { mutableStateOf(false) }

    fun pickApk(target: String) {
        // Use ActivityResultContracts.OpenDocument via a launcher we create below.
    }

    // MIME types: regular APK + ZIP (covers .apks) + octet-stream (fallback).
    // Same rationale as PickerScreen — see comment there.
    val pickMimes = arrayOf(
        "application/vnd.android.package-archive",
        "application/zip",
        "application/octet-stream",
    )

    // PANIC/FREEZE SAFETY (IMPL-004):
    // Same as PickerScreen — `onResult` runs on the MAIN THREAD, and
    // `copyUriToCacheExt` does file I/O that can block for seconds on a
    // large APK. We dispatch to Dispatchers.IO and gate the UI with
    // `copying` so the user sees a "Copying…" state on the button.
    val pickOld = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                copying = true
                scope.launch {
                    // Preserve source extension (.apk / .apks) so the Rust
                    // `open_any` dispatcher routes .apks through the container path.
                    val cache = withContext(Dispatchers.IO) {
                        copyUriToCacheExt(context, uri, "diff_old")
                    }
                    if (cache != null) {
                        oldPath = cache.absolutePath
                        oldLabel = cache.name
                    }
                    copying = false
                }
            }
        },
    )
    val pickNew = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                copying = true
                scope.launch {
                    val cache = withContext(Dispatchers.IO) {
                        copyUriToCacheExt(context, uri, "diff_new")
                    }
                    if (cache != null) {
                        newPath = cache.absolutePath
                        newLabel = cache.name
                    }
                    copying = false
                }
            }
        },
    )

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("Diff two APKs") },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                }
            },
        )
    }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedButton(
                onClick = { pickOld.launch(pickMimes) },
                enabled = !copying && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (copying) "Copying…" else "Pick OLD: $oldLabel") }

            OutlinedButton(
                onClick = { pickNew.launch(pickMimes) },
                enabled = !copying && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (copying) "Copying…" else "Pick NEW: $newLabel") }

            Button(
                onClick = {
                    val o = oldPath; val n = newPath
                    if (o == null || n == null) return@Button
                    busy = true
                    scope.launch {
                        result = withContext(Dispatchers.IO) { NativeBridge.diff(o, n) }
                        busy = false
                    }
                },
                enabled = oldPath != null && newPath != null && !busy && !copying,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Diffing…" else "Run diff") }

            result?.let { r ->
                Divider()
                when (r) {
                    is ScanResult.Ok -> {
                        Text("Diff result:", style = MaterialTheme.typography.titleSmall)
                        MarkdownRenderer(
                            markdown = r.markdown,
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                    is ScanResult.Err -> {
                        Text(
                            "Error: ${r.message}",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}
