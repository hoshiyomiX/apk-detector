package id.zai.apkdetector.ui.screens

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.CompareArrows
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PickerScreen(
    onScan: (String) -> Unit,
    onDiff: () -> Unit,
    onHistory: () -> Unit,
) {
    val context = LocalContext.current
    var pendingPath by remember { mutableStateOf<String?>(null) }

    // SAF picker for APK files (handles "permission denied" edge case on API 30+)
    val pickApk = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) {
                // Copy URI → cache file, then scan the cache path.
                val cache = java.io.File(context.cacheDir, "picked_${System.currentTimeMillis()}.apk")
                try {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        cache.outputStream().use { out -> input.copyTo(out) }
                    }
                    pendingPath = cache.absolutePath
                } catch (_: Throwable) { /* fall through */ }
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
                "Pick an APK to analyze which defense mechanisms it ships.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Scans run entirely on-device. No data leaves your phone.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Button(
                onClick = { pickApk.launch(arrayOf("application/vnd.android.package-archive")) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Pick APK")
            }

            OutlinedButton(onClick = onDiff, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.CompareArrows, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Diff two versions")
            }

            OutlinedButton(onClick = onHistory, modifier = Modifier.fillMaxWidth()) {
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
