package id.zai.apkdetector.ui.screens

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.ApkDetectorApp
import id.zai.apkdetector.data.ApkSource
import id.zai.apkdetector.data.copyUriToCacheExt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PickerScreen(
    onScan: (String) -> Unit,
    onHistory: () -> Unit,
    onInstalledApps: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pendingPath by remember { mutableStateOf<String?>(null) }
    var copying by remember { mutableStateOf(false) }

    // SAF picker for APK and .apks files.
    // - `application/vnd.android.package-archive` covers regular .apk files.
    // - `application/zip` covers .apks (BundleTool output is a ZIP-of-APKs).
    // - `application/octet-stream` is a fallback for .apks files registered
    //   with a generic binary MIME type on some Android versions.
    //
    // PANIC/FREEZE SAFETY (IMPL-003):
    // The `onResult` callback runs on the MAIN THREAD. The original code
    // called `copyUriToCacheExt` synchronously inside it — for a 100MB APK
    // this blocked the main thread for several seconds, causing freeze/ANR.
    // We now launch a coroutine on Dispatchers.IO to perform the cache
    // copy, then set `pendingPath` on the main thread. The UI shows a
    // "Copying…" state via the `copying` flag so the user knows what's
    // happening.
    val pickApk = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                copying = true
                scope.launch {
                    // Copy URI → cache file with preserved extension, then scan.
                    // The Rust `open_any` dispatcher detects `.apks` containers
                    // by extension, so we MUST preserve `.apk`/`.apks` rather
                    // than hardcoding `.apk`.
                    val cache = withContext(Dispatchers.IO) {
                        copyUriToCacheExt(context, uri, "picked")
                    }
                    if (cache != null) {
                        pendingPath = cache.absolutePath
                    }
                    copying = false
                }
            }
        },
    )

    Scaffold(topBar = {
        TopAppBar(title = { Text("APK Detector") })
    }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Pick an APK or .apks (BundleTool) to analyze which defense mechanisms it ships.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Scans run entirely on-device. No data leaves your phone.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Button(
                onClick = {
                    pickApk.launch(
                        arrayOf(
                            "application/vnd.android.package-archive",
                            "application/zip",
                            "application/octet-stream",
                        ),
                    )
                },
                enabled = !copying,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (copying) "Copying to cache…" else "Pick APK / .apks")
            }

            // Scan an installed app — opens the InstalledAppsScreen which
            // lists all packages via PackageManager. The user picks one,
            // we read its `applicationInfo.sourceDir` (a real filesystem
            // path to base.apk) and pass it to NativeBridge.scan directly.
            // No file copying needed (unlike SAF picker flow).
            OutlinedButton(onClick = onInstalledApps, enabled = !copying, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Apps, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Scan installed app")
            }

            OutlinedButton(onClick = onHistory, enabled = !copying, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.History, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("History")
            }

            Divider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                "Engine version: ${id.zai.apkdetector.data.NativeBridge.version()}",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
            )

            pendingPath?.let { path ->
                LaunchedEffect(path) { onScan(path) }
            }
        }
    }
}
