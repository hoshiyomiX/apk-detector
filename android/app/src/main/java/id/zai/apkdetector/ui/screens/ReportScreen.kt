package id.zai.apkdetector.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.data.ScanResultCache
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * Report screen — renders the static Markdown scan report for a single APK.
 *
 * ## Architecture
 *
 * The Markdown is loaded from [ScanResultCache] (populated by
 * `ScanProgressScreen` after the scan completes). On cache miss (process
 * death, deep-link, recomposition after rotation), the screen falls back
 * to a fresh `NativeBridge.scan(apkPath)` call.
 *
 * ## Why this layout
 *
 * The previous version passed the entire Markdown through the nav route as
 * a URL-encoded argument. This was the root cause of the `%J` crash fixed
 * in IMPL-001 — Navigation Compose's `Uri.decode()` throws on malformed
 * `%XX` escapes, and the Markdown can contain literal `%` characters (e.g.,
 * when the APK path embeds them). The current design passes only the
 * (short, URL-safe) APK path and uses an in-memory cache for the bulk
 * Markdown payload.
 *
 * ## Device self-scan moved out
 *
 * A previous iteration of this screen had a "Device Simulation" section
 * with preset profile chips (clean / rooted-magisk / emulator / etc.).
 * The user clarified that what they wanted was detection on the LIVE
 * device, not preset-based simulation — see [DeviceScanScreen] for the
 * new live-device self-scan feature, accessible from the PickerScreen
 * without needing to scan an APK first.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(
    apkPath: String,
    onBack: () -> Unit,
) {
    val context = LocalContext.current

    // Initialize from cache (populated by ScanProgressScreen). If empty,
    // we trigger a fresh scan below.
    var markdown by remember(apkPath) {
        mutableStateOf(ScanResultCache.get(apkPath) ?: "")
    }
    var loading by remember(apkPath) { mutableStateOf(markdown.isEmpty()) }
    var error by remember(apkPath) { mutableStateOf<String?>(null) }

    // Load static report — either from cache (instant) or by re-scanning.
    LaunchedEffect(apkPath) {
        if (markdown.isEmpty()) {
            loading = true
            val result = withContext(Dispatchers.IO) { NativeBridge.scan(apkPath) }
            if (!isActive) return@LaunchedEffect
            when (result) {
                is ScanResult.Ok -> {
                    markdown = result.markdown
                    ScanResultCache.put(apkPath, result.markdown)
                }
                is ScanResult.Err -> error = result.message
            }
            loading = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Report") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        enabled = markdown.isNotEmpty(),
                        onClick = {
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/markdown"
                                putExtra(Intent.EXTRA_TEXT, markdown)
                                putExtra(Intent.EXTRA_SUBJECT, "APK Detector Report")
                            }
                            context.startActivity(Intent.createChooser(intent, "Share report"))
                        },
                    ) {
                        Icon(Icons.Default.Share, contentDescription = "Share")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            when {
                loading -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            CircularProgressIndicator()
                            Text("Running scan…", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                error != null -> {
                    Text(
                        "Error: $error",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                markdown.isNotEmpty() -> {
                    MarkdownRenderer(
                        markdown = markdown,
                        modifier = Modifier.fillMaxWidth(),
                        scrollable = false,
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}
