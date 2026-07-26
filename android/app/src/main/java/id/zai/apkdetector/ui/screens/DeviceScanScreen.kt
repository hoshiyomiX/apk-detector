package id.zai.apkdetector.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.data.DeviceProbe
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * Device Self-Scan screen — runs the Rust verdict table against the LIVE
 * device's state (gathered by [DeviceProbe]) WITHOUT requiring an APK.
 *
 * ## What this answers
 *
 *   "What would detect me on this phone?" — i.e., which defense rules from
 *   defended APKs (banking apps, DRM-protected media, anti-cheat games)
 *   would TRIGGER on the user's actual device, vs which would BYPASS, vs
 *   which are indeterminate.
 *
 * ## Architecture
 *
 *   1. On entry, [LaunchedEffect] runs:
 *      - `DeviceProbe.gather(context)` — gathers ~14 device signals from
 *        Android APIs (Build, Settings, PackageManager, /proc/self/maps,
 *        etc.) → JSON matching Rust's `DeviceProfile` schema.
 *      - `NativeBridge.deviceScan(profileJson)` — passes the JSON to the
 *        Rust JNI export, which walks the verdict table and produces a
 *        Markdown report.
 *   2. The Markdown is rendered via [MarkdownRenderer].
 *   3. A PASS/FAIL verdict badge is computed from the "Findings:" line in
 *      the Markdown. PASS = no detections triggered (the user's device
 *        would not be blocked by typical defended APKs). FAIL = N
 *        detections triggered (the user's device would be blocked or
 *        restricted).
 *
 * ## Refresh
 *
 * The user can pull a refresh via the top-bar action — re-gathers the
 * device profile and re-runs the scan. Useful after toggling a setting
 * (e.g., disabling Developer Options) to see the updated verdict.
 *
 * ## Threading
 *
 * `DeviceProbe.gather` is fast (<20ms typical — file stats + Build fields)
 * but `NativeBridge.deviceScan` is synchronous and runs the verdict table
 * (~48 rules). Both run on `Dispatchers.IO` to avoid blocking the UI.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceScanScreen(
    onBack: () -> Unit,
) {
    val context = LocalContext.current

    var markdown by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    // Refresh trigger — incrementing this re-runs the LaunchedEffect.
    var refreshTrigger by remember { mutableStateOf(0) }

    // Run the device self-scan on entry + on refresh.
    LaunchedEffect(refreshTrigger) {
        loading = true
        error = null
        markdown = null
        val result = withContext(Dispatchers.IO) {
            val profileJson = DeviceProbe.gather(context)
            NativeBridge.deviceScan(profileJson)
        }
        if (!isActive) return@LaunchedEffect
        when (result) {
            is ScanResult.Ok -> markdown = result.markdown
            is ScanResult.Err -> error = result.message
        }
        loading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Device Self-Scan") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        enabled = !loading,
                        onClick = { refreshTrigger++ },
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = "Re-run scan")
                    }
                    IconButton(
                        enabled = markdown != null,
                        onClick = {
                            val md = markdown ?: return@IconButton
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/markdown"
                                putExtra(Intent.EXTRA_TEXT, md)
                                putExtra(Intent.EXTRA_SUBJECT, "APK Detector — Device Self-Scan")
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
            // Intro text — explain what this screen does.
            Text(
                "This scan runs the detection verdict table against your " +
                    "device's live state. No APK needed — it answers " +
                    "\"what would detect me on this phone?\".",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )

            // Verdict badge — shown only after the scan completes.
            markdown?.let { md ->
                val counts = parseDeviceScanCounts(md)
                if (counts != null) {
                    val (triggered, _, _) = counts
                    val verdictText = if (triggered == 0) {
                        "✓ PASS — no detections would fire on this device"
                    } else {
                        "✗ FAIL — $triggered detection(s) would block you"
                    }
                    val verdictColor = if (triggered == 0) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    }
                    Surface(
                        color = verdictColor.copy(alpha = 0.12f),
                        tonalElevation = 0.dp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                    ) {
                        Text(
                            verdictText,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = verdictColor,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }

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
                            Text(
                                "Probing device state…",
                                style = MaterialTheme.typography.bodyMedium,
                            )
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
                markdown != null -> {
                    MarkdownRenderer(
                        markdown = markdown!!,
                        modifier = Modifier.fillMaxWidth(),
                        scrollable = false,
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/**
 * Parse the device-scan Markdown's "Findings:" header line to extract the
 * triggered / bypassed / unknown counts.
 *
 * The line looks like:
 *   `**Findings:** 27 total — 1 triggered, 26 bypassed, 0 unknown`
 *
 * Same format as the simulation Markdown in [ReportScreen], so the regex
 * is identical. Returns `null` if the line is missing or unparseable.
 */
private fun parseDeviceScanCounts(md: String): Triple<Int, Int, Int>? {
    val regex = Regex(
        pattern = """(\d+)\s+total\s+—\s+(\d+)\s+triggered,\s+(\d+)\s+bypassed,\s+(\d+)\s+unknown""",
    )
    val match = regex.find(md) ?: return null
    val (_, triggered, bypassed, unknown) = match.destructured
    return Triple(
        triggered.toIntOrNull() ?: return null,
        bypassed.toIntOrNull() ?: return null,
        unknown.toIntOrNull() ?: return null,
    )
}
