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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.data.DeviceProfile
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.data.ScanResultCache
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * Report screen — renders the static Markdown scan report plus an on-demand
 * device simulation section.
 *
 * ## Architecture
 *
 *   1. Static report: loaded from [ScanResultCache] (populated by
 *      `ScanProgressScreen`). On cache miss (process death, deep-link),
 *      falls back to a fresh `NativeBridge.scan(apkPath)` call.
 *   2. Simulation: a row of `FilterChip`s, one per [DeviceProfile.presets]
 *      key. Selecting a chip runs `NativeBridge.scanSimulated(apkPath,
 *      profileJson)` and renders the result below. The user sees a
 *      PASS/FAIL verdict badge computed from the "Findings:" line in the
 *      simulation Markdown.
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
 * ## Simulation verdict
 *
 * The simulation Markdown contains a header line like:
 *   `**Findings:** 27 total — 1 triggered, 26 bypassed, 0 unknown`
 *
 * We parse this line to extract the `triggered` count. If `triggered == 0`,
 * the device PASSES (no detections fired). Otherwise it FAILS — the user
 * is blocked/restricted on this device profile.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ReportScreen(
    apkPath: String,
    onBack: () -> Unit,
) {
    val context = LocalContext.current

    // ─── Static report state ────────────────────────────────────────────
    // Initialize from cache (populated by ScanProgressScreen). If empty,
    // we trigger a fresh scan below.
    var markdown by remember(apkPath) {
        mutableStateOf(ScanResultCache.get(apkPath) ?: "")
    }
    var reportLoading by remember(apkPath) { mutableStateOf(markdown.isEmpty()) }
    var reportError by remember(apkPath) { mutableStateOf<String?>(null) }

    // ─── Simulation state ───────────────────────────────────────────────
    // `selectedProfile` is null until the user taps a chip. Tapping the
    // active chip again deselects it (back to null).
    var selectedProfile by remember { mutableStateOf<String?>(null) }
    var simMarkdown by remember(apkPath) { mutableStateOf<String?>(null) }
    var simLoading by remember(apkPath) { mutableStateOf(false) }
    var simError by remember(apkPath) { mutableStateOf<String?>(null) }

    // Load static report — either from cache (instant) or by re-scanning.
    LaunchedEffect(apkPath) {
        if (markdown.isEmpty()) {
            reportLoading = true
            val result = withContext(Dispatchers.IO) { NativeBridge.scan(apkPath) }
            if (!isActive) return@LaunchedEffect
            when (result) {
                is ScanResult.Ok -> {
                    markdown = result.markdown
                    ScanResultCache.put(apkPath, result.markdown)
                }
                is ScanResult.Err -> reportError = result.message
            }
            reportLoading = false
        }
    }

    // Run simulation whenever the selected profile changes. The simulation
    // re-runs the static scan internally (Rust `scan_apk_simulated`), so it
    // takes roughly the same time as the original scan — ~3-5s on a mid-range
    // device for a 100MB APK. The user sees a progress indicator while it
    // runs.
    LaunchedEffect(selectedProfile, apkPath) {
        val profileKey = selectedProfile
        if (profileKey == null) {
            simMarkdown = null
            simError = null
            return@LaunchedEffect
        }
        val profileJson = DeviceProfile.presets[profileKey]
        if (profileJson == null) {
            simError = "Unknown profile: $profileKey"
            return@LaunchedEffect
        }
        simLoading = true
        simError = null
        simMarkdown = null
        val result = withContext(Dispatchers.IO) {
            NativeBridge.scanSimulated(apkPath, profileJson)
        }
        if (!isActive) return@LaunchedEffect
        when (result) {
            is ScanResult.Ok -> simMarkdown = result.markdown
            is ScanResult.Err -> simError = result.message
        }
        simLoading = false
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
            // ─── Static scan report ──────────────────────────────────────
            when {
                reportLoading -> {
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
                reportError != null -> {
                    Text(
                        "Error: $reportError",
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

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // ─── Device simulation section ──────────────────────────────
            //
            // The user picks a device profile from the curated presets in
            // `DeviceProfile.presets`. Tapping a chip runs the simulation
            // and shows the result below. The verdict badge gives an
            // at-a-glance PASS/FAIL answer.
            Text(
                "Device Simulation",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
            Text(
                "Pick a device profile to see which detections would TRIGGER " +
                    "(block the user) vs BYPASS (user's setup defeats them) on " +
                    "that device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )

            // Verdict badge — shown only after a simulation completes.
            simMarkdown?.let { md ->
                val counts = parseSimCounts(md)
                if (counts != null) {
                    val (triggered, _, _) = counts
                    val verdictText = if (triggered == 0) {
                        "✓ PASS — no detections triggered on this device"
                    } else {
                        "✗ FAIL — $triggered detection(s) would block the user"
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

            // Profile chip row — FlowRow wraps chips to the next line if
            // they don't fit horizontally.
            FlowRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                DeviceProfile.presets.keys.forEach { profileKey ->
                    FilterChip(
                        selected = selectedProfile == profileKey,
                        onClick = {
                            selectedProfile = if (selectedProfile == profileKey) null else profileKey
                        },
                        label = { Text(profileKey) },
                    )
                }
            }

            // Simulation output — either loading, error, or rendered
            // Markdown. The simulation Markdown is rendered with
            // `scrollable = false` because the outer Column already scrolls.
            when {
                simLoading -> {
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
                                "Running simulation…",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                }
                simError != null -> {
                    Text(
                        "Simulation error: $simError",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(16.dp),
                    )
                }
                simMarkdown != null -> {
                    MarkdownRenderer(
                        markdown = simMarkdown!!,
                        modifier = Modifier.fillMaxWidth(),
                        scrollable = false,
                    )
                }
                selectedProfile == null -> {
                    Text(
                        "Tap a profile above to simulate.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/**
 * Parse the simulation Markdown's "Findings:" header line to extract the
 * triggered / bypassed / unknown counts.
 *
 * The line looks like:
 *   `**Findings:** 27 total — 1 triggered, 26 bypassed, 0 unknown`
 *
 * Returns `null` if the line is missing or unparseable (in which case the
 * UI just omits the verdict badge and shows the raw Markdown).
 */
private fun parseSimCounts(md: String): Triple<Int, Int, Int>? {
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
