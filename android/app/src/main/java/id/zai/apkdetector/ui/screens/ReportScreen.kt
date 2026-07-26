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
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.data.ScanResultCache
import id.zai.apkdetector.data.SimulationResultCache
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * Report screen — renders the static Markdown scan report for a single APK
 * PLUS the auto-chained blocking-only device simulation.
 *
 * ## Architecture
 *
 * Both the scan Markdown and the simulation Markdown are loaded from
 * [ScanResultCache] + [SimulationResultCache] (populated by
 * `ScanProgressScreen` via `Repository.scanWithAutoSimulation` after the
 * chain completes). On cache miss (process death, deep-link, recomposition
 * after rotation), the screen falls back to:
 *   - A fresh `NativeBridge.scan(apkPath)` call for the scan report.
 *   - A `null` simulation block (the auto-chain only runs from
 *     `ScanProgressScreen`; if we land here via HistoryScreen or deep
 *     link, we don't have a live device profile to re-run the simulation
 *     against). The user sees a hint to re-scan from the picker if they
 *     want the simulation.
 *
 * ## Why this layout
 *
 * The previous version passed the entire Markdown through the nav route as
 * a URL-encoded argument. This was the root cause of the `%J` crash fixed
 * in IMPL-001 — Navigation Compose's `Uri.decode()` throws on malformed
 * `%XX` escapes, and the Markdown can contain literal `%` characters (e.g.,
 * when the APK path embeds them). The current design passes only the
 * (short, URL-safe) APK path and uses in-memory caches for the bulk
 * Markdown payloads.
 *
 * ## Auto-chained simulation
 *
 * As of stellar-trails v9.9.1, the user's requested flow is:
 *   1. scan apk target →
 *   2. data result 'blocking-only filter' diperoleh →
 *   3. auto simulasi sesuai data result →
 *   4. rangkuman hasil test
 *
 * Steps 2-4 happen automatically inside `Repository.scanWithAutoSimulation`
 * and the simulation Markdown is cached in [SimulationResultCache]. This
 * screen renders:
 *
 *   - A "## Device Simulation Summary" section at the top — parses the
 *     "Overall Verdict" banner from the simulation Markdown and shows
 *     a colored PASS / FAIL / INCONCLUSIVE / NO BLOCKING DETECTIONS /
 *     SIMULATION ERROR badge. The badge is the "rangkuman hasil test"
 *     the user wants.
 *   - The full APK scan Markdown below.
 *   - The full simulation Markdown below that (so the user can drill
 *     into per-rule details if they want).
 *
 * ## Device self-scan moved out
 *
 * A previous iteration of this screen had a "Device Simulation" section
 * with preset profile chips (clean / rooted-magisk / emulator / etc.).
 * The user clarified that what they wanted was detection on the LIVE
 * device, not preset-based simulation — see [DeviceScanScreen] for the
 * standalone live-device self-scan feature, accessible from the
 * PickerScreen without needing to scan an APK first.
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
    // Simulation Markdown — populated by Repository.scanWithAutoSimulation.
    // Null on cache miss (e.g., arrived via HistoryScreen or deep-link
    // without going through ScanProgressScreen).
    var simMarkdown by remember(apkPath) {
        mutableStateOf(SimulationResultCache.get(apkPath))
    }
    var loading by remember(apkPath) { mutableStateOf(markdown.isEmpty()) }
    var error by remember(apkPath) { mutableStateOf<String?>(null) }

    // Load static report — either from cache (instant) or by re-scanning.
    // We do NOT auto-re-run the simulation here because it requires the
    // live device profile (Play Integrity + DeviceProbe). The user can
    // re-run the full chain by re-scanning from PickerScreen.
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
                            val combined = buildString {
                                append(markdown)
                                if (!simMarkdown.isNullOrEmpty()) {
                                    append("\n\n---\n\n")
                                    append(simMarkdown)
                                }
                            }
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/markdown"
                                putExtra(Intent.EXTRA_TEXT, combined)
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
            // ── Device Simulation Summary (rangkuman hasil test) ───────────
            //
            // Shown ABOVE the scan report so the user sees the pass/fail
            // verdict immediately on entering the screen. Falls back to
            // a hint card if the simulation cache is empty (arrived via
            // HistoryScreen or process death).
            simMarkdown?.let { simMd ->
                SimulationSummaryCard(simMd)
            } ?: run {
                if (!loading && error == null) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        tonalElevation = 0.dp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                    ) {
                        Text(
                            "Device simulation not available for this report. " +
                                "Re-scan from the home screen to auto-run the " +
                                "blocking-only simulation + Play Integrity check.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            }

            // ── Scan report ────────────────────────────────────────────────
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

            // ── Full simulation markdown (per-rule detail) ─────────────────
            //
            // Rendered BELOW the scan report so the user can drill into
            // the per-rule simulation verdicts after reading the scan
            // summary. The Overall Verdict banner appears at the top of
            // this markdown block too — that's intentional, it's how the
            // Rust renderer emits it.
            simMarkdown?.let { simMd ->
                Spacer(Modifier.height(24.dp))
                HorizontalDivider()
                Spacer(Modifier.height(16.dp))
                MarkdownRenderer(
                    markdown = simMd,
                    modifier = Modifier.fillMaxWidth(),
                    scrollable = false,
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/**
 * Card showing the Overall Verdict from the blocking-only simulation
 * Markdown. Parses the "## Overall Verdict" section to determine
 * PASS / FAIL / INCONCLUSIVE / NO BLOCKING DETECTIONS / SIMULATION ERROR
 * and renders a colored badge accordingly.
 *
 * This IS the "rangkuman hasil test" the user requested — a single
 * glance at the top of the report tells them whether the APK would
 * block them on their current device.
 *
 * If parsing fails, the card is hidden (the full simulation Markdown
 * further down still shows the verdict banner in its raw form).
 *
 * @param simMd The simulation Markdown produced by
 *   `NativeBridge.scanSimulatedBlocking` (via
 *   `Repository.scanWithAutoSimulation`).
 */
@Composable
private fun SimulationSummaryCard(simMd: String) {
    val verdict = parseOverallVerdict(simMd) ?: return

    val (badgeText, badgeColor) = when (verdict) {
        OverallVerdict.PASS -> "✓ PASS" to MaterialTheme.colorScheme.primary
        OverallVerdict.FAIL -> "✗ FAIL" to MaterialTheme.colorScheme.error
        OverallVerdict.INCONCLUSIVE -> "⚠ INCONCLUSIVE" to
            MaterialTheme.colorScheme.tertiary
        OverallVerdict.NO_BLOCKING -> "⚪ NO BLOCKING DETECTIONS" to
            MaterialTheme.colorScheme.secondary
        OverallVerdict.SIM_ERROR -> "⚠ SIMULATION ERROR" to
            MaterialTheme.colorScheme.error
    }

    // Extract the explanation line that follows the "**...**" verdict
    // line in the Overall Verdict section.
    val explanation = extractVerdictExplanation(simMd) ?: ""

    Surface(
        color = badgeColor.copy(alpha = 0.12f),
        tonalElevation = 0.dp,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "Device Simulation Summary",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                badgeText,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = badgeColor,
            )
            if (explanation.isNotEmpty()) {
                Text(
                    explanation,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            Text(
                "Verdict applies to your current device only — re-scan after " +
                    "changing device state (toggling Developer Options, etc.).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * The five possible overall verdicts emitted by the Rust
 * `to_markdown_blocking_simulation` renderer.
 */
private enum class OverallVerdict {
    PASS,
    FAIL,
    INCONCLUSIVE,
    NO_BLOCKING,
    SIM_ERROR,
}

/**
 * Parse the "## Overall Verdict" section of the simulation Markdown to
 * determine which verdict was emitted. Returns null if the section is
 * missing or unparseable.
 */
private fun parseOverallVerdict(simMd: String): OverallVerdict? {
    // The verdict line looks like one of:
    //   **✓ PASS — all blocking detections are bypassed on this device. ...**
    //   **✗ FAIL — at least one blocking detection would fire on this device. ...**
    //   **⚠ INCONCLUSIVE — ...**
    //   **⚪ NO BLOCKING DETECTIONS — ...**
    //   **⚠ SIMULATION ERROR — ...**
    //
    // We do a substring check rather than a full regex — the marker
    // symbols (✓ ✗ ⚠ ⚪) are unique enough to disambiguate.
    return when {
        simMd.contains("✓ PASS —") -> OverallVerdict.PASS
        simMd.contains("✗ FAIL —") -> OverallVerdict.FAIL
        simMd.contains("⚠ INCONCLUSIVE —") -> OverallVerdict.INCONCLUSIVE
        simMd.contains("⚪ NO BLOCKING DETECTIONS —") -> OverallVerdict.NO_BLOCKING
        simMd.contains("⚠ SIMULATION ERROR —") -> OverallVerdict.SIM_ERROR
        else -> null
    }
}

/**
 * Extract the human-readable explanation that follows the verdict marker.
 * E.g., for "**✗ FAIL — at least one blocking detection would fire on this
 * device. The user CANNOT use the app without changing their setup or
 * applying a bypass.**", returns "at least one blocking detection would
 * fire on this device. The user CANNOT use the app without changing
 * their setup or applying a bypass."
 *
 * Returns null if the explanation can't be extracted.
 */
private fun extractVerdictExplanation(simMd: String): String? {
    // Find the verdict line — starts with "**" and contains one of the
    // marker symbols.
    val markerPatterns = listOf(
        "✓ PASS — ",
        "✗ FAIL — ",
        "⚠ INCONCLUSIVE — ",
        "⚪ NO BLOCKING DETECTIONS — ",
        "⚠ SIMULATION ERROR — ",
    )
    for (marker in markerPatterns) {
        val idx = simMd.indexOf(marker)
        if (idx >= 0) {
            // Start after the marker, end at the closing "**"
            val start = idx + marker.length
            val end = simMd.indexOf("**", start)
            if (end > start) {
                return simMd.substring(start, end).trim()
            }
        }
    }
    return null
}
