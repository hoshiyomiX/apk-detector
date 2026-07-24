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

    fun pickApk(target: String) {
        // Use ActivityResultContracts.OpenDocument via a launcher we create below.
    }

    val pickOld = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                val cache = File(context.cacheDir, "diff_old_${System.currentTimeMillis()}.apk")
                context.contentResolver.openInputStream(uri)?.use { input ->
                    cache.outputStream().use { out -> input.copyTo(out) }
                }
                oldPath = cache.absolutePath
                oldLabel = cache.name
            }
        },
    )
    val pickNew = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                val cache = File(context.cacheDir, "diff_new_${System.currentTimeMillis()}.apk")
                context.contentResolver.openInputStream(uri)?.use { input ->
                    cache.outputStream().use { out -> input.copyTo(out) }
                }
                newPath = cache.absolutePath
                newLabel = cache.name
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
                onClick = { pickOld.launch(arrayOf("application/vnd.android.package-archive")) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pick OLD: $oldLabel") }

            OutlinedButton(
                onClick = { pickNew.launch(arrayOf("application/vnd.android.package-archive")) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pick NEW: $newLabel") }

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
                enabled = oldPath != null && newPath != null && !busy,
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
