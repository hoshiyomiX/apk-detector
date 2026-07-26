package id.zai.apkdetector.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.BuildConfig
import id.zai.apkdetector.data.DeviceProbe
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.PlayIntegrityClient
import id.zai.apkdetector.data.ScanResult
import id.zai.apkdetector.markdown.MarkdownRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
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
 *   1. On entry (or refresh), the screen runs:
 *      - `DeviceProbe.gather(context, playIntegrityPasses)` — gathers
 *        ~14 device signals from Android APIs (Build, Settings,
 *        PackageManager, /proc/self/maps, etc.) → JSON matching Rust's
 *        `DeviceProfile` schema. The `play_integrity_passes` field is
 *        populated only if the user has opted in to the Play Integrity
 *        check (see below).
 *      - `NativeBridge.deviceScan(profileJson)` — passes the JSON to the
 *        Rust JNI export, which walks the verdict table and produces a
 *        Markdown report.
 *   2. The Markdown is rendered via [MarkdownRenderer].
 *   3. A PASS/FAIL verdict badge is computed from the "Findings:" line
 *      in the Markdown.
 *
 * ## Play Integrity opt-in
 *
 *   The Play Integrity API call is asynchronous (1-3s) and requires a
 *   Google Cloud Project Number configured via the
 *   `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` env var at build time. If not
 *   configured, the toggle is hidden. If configured, the user can tap
 *   the shield icon in the top bar to:
 *     - Run the Play Integrity Standard Request flow.
 *     - Receive a [PlayIntegrityClient.Result] (Passes / NotConfigured /
 *       Error) and pass it to the next [DeviceProbe.gather] call.
 *
 *   This is opt-in (not automatic) because:
 *     1. The API call has network latency and may fail on devices
 *        without Google Play services.
 *     2. The token issuance itself is the signal — there's no need to
 *        call it on every scan.
 *     3. Some users may want to see the device-scan WITHOUT Play
 *        Integrity to compare verdicts.
 *
 * ## Refresh
 *
 *   The Refresh icon in the top bar re-gathers the device profile and
 *   re-runs the scan. If Play Integrity was previously run, its cached
 *   result is reused (no re-call) unless the user explicitly re-runs it
 *   via the shield icon.
 *
 * ## Threading
 *
 *   `DeviceProbe.gather` is fast (<20ms typical — file stats + Build
 *   fields) but `NativeBridge.deviceScan` is synchronous and runs the
 *   verdict table (~48 rules). `PlayIntegrityClient.requestVerdict` is
 *   async with up to 15s warm-up + 10s token request. All run on
 *   `Dispatchers.IO` to avoid blocking the UI.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceScanScreen(
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var markdown by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    // Refresh trigger — incrementing this re-runs the LaunchedEffect.
    var refreshTrigger by remember { mutableStateOf(0) }

    // ── Play Integrity state ────────────────────────────────────────────
    //
    // playIntegrityPasses: the latest verdict from PlayIntegrityClient.
    //   null = not run yet (or cleared).
    //   true / false = definitive verdict.
    //
    // playIntegrityStatus: human-readable status for the inline banner.
    //
    // playIntegrityJob: tracks the in-flight API call so we can cancel
    //   it if the user taps the button again (debounce).
    //
    // playIntegrityConfigured: whether the build has a non-zero cloud
    //   project number. If false, the shield icon is hidden.
    val playIntegrityConfigured =
        BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER != 0L
    var playIntegrityPasses by remember { mutableStateOf<Boolean?>(null) }
    var playIntegrityStatus by remember { mutableStateOf<String?>(null) }
    var playIntegrityInFlight by remember { mutableStateOf(false) }
    var playIntegrityJob by remember { mutableStateOf<Job?>(null) }

    // Run the device self-scan on entry + on refresh.
    LaunchedEffect(refreshTrigger) {
        loading = true
        error = null
        markdown = null
        val result = withContext(Dispatchers.IO) {
            val profileJson = DeviceProbe.gather(
                context = context,
                playIntegrityPasses = playIntegrityPasses,
            )
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
                    // Play Integrity toggle — only shown if the build has
                    // a non-zero cloud project number configured.
                    if (playIntegrityConfigured) {
                        IconButton(
                            enabled = !playIntegrityInFlight,
                            onClick = {
                                // Cancel any in-flight call (debounce).
                                playIntegrityJob?.cancel()
                                playIntegrityJob = scope.launch {
                                    playIntegrityInFlight = true
                                    playIntegrityStatus = "Calling Play Integrity API…"
                                    val result = PlayIntegrityClient.requestVerdict(context)
                                    playIntegrityPasses = when (result) {
                                        is PlayIntegrityClient.Result.Passes -> result.value
                                        PlayIntegrityClient.Result.NotConfigured -> {
                                            playIntegrityStatus =
                                                "Not configured — set PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER"
                                            null
                                        }
                                        is PlayIntegrityClient.Result.Error -> {
                                            playIntegrityStatus =
                                                "Error: ${result.message}" +
                                                    (result.errorCode?.let { " (code $it)" } ?: "")
                                            null
                                        }
                                    }
                                    if (result is PlayIntegrityClient.Result.Passes) {
                                        playIntegrityStatus = if (result.value) {
                                            "Play Integrity: PASS (token issued)"
                                        } else {
                                            "Play Integrity: FAIL (non-genuine device)"
                                        }
                                    }
                                    playIntegrityInFlight = false
                                    // Re-run the device scan with the new verdict.
                                    refreshTrigger++
                                }
                            },
                        ) {
                            if (playIntegrityInFlight) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    strokeWidth = 2.dp,
                                )
                            } else {
                                Icon(
                                    Icons.Default.Security,
                                    contentDescription = "Run Play Integrity check",
                                    tint = when (playIntegrityPasses) {
                                        true -> MaterialTheme.colorScheme.primary
                                        false -> MaterialTheme.colorScheme.error
                                        null -> MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            }
                        }
                    }
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

            // Play Integrity status banner — shown when the user has
            // interacted with the shield icon, or when the check is
            // in-flight.
            if (playIntegrityConfigured && playIntegrityStatus != null) {
                Surface(
                    color = when (playIntegrityPasses) {
                        true -> MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                        false -> MaterialTheme.colorScheme.error.copy(alpha = 0.12f)
                        null -> MaterialTheme.colorScheme.surfaceVariant
                    },
                    tonalElevation = 0.dp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                ) {
                    Text(
                        playIntegrityStatus!!,
                        style = MaterialTheme.typography.bodySmall,
                        color = when (playIntegrityPasses) {
                            true -> MaterialTheme.colorScheme.primary
                            false -> MaterialTheme.colorScheme.error
                            null -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.padding(12.dp),
                    )
                }
            } else if (!playIntegrityConfigured) {
                // Hint to the user that Play Integrity could be wired if
                // they configure the cloud project number.
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    tonalElevation = 0.dp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                ) {
                    Text(
                        "Play Integrity check not configured — set " +
                            "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER at build " +
                            "time to enable real attestation.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(12.dp),
                    )
                }
            }

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
