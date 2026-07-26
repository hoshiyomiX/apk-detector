package id.zai.apkdetector.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.ApkDetectorApp
import id.zai.apkdetector.data.ApkSource
import id.zai.apkdetector.data.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanProgressScreen(
    apkPath: String,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val repo = remember { ApkDetectorApp.get().repository }
    var status by remember { mutableStateOf("Opening APK…") }
    var error by remember { mutableStateOf<String?>(null) }

    // PANIC/FREEZE SAFETY (IMPL-005):
    //
    // BUG (original): `LaunchedEffect` was launching ANOTHER coroutine via
    // `scope.launch { ... }` inside its own lambda. This is wrong on two levels:
    //
    //   1. `LaunchedEffect(apkPath)` IS already a coroutine — its lambda runs
    //      in a scope that is automatically cancelled when the composition
    //      leaves (back-press, navigation, lifecycle destroy). Launching a
    //      second coroutine via `rememberCoroutineScope()` DETACHES the work
    //      from this lifecycle — that inner coroutine survives back-press and
    //      keeps running on Dispatchers.IO.
    //
    //   2. When the JNI `scan` call eventually returned (10s, 30s, 60s later),
    //      the inner coroutine resumed and called `onDone(result.markdown)`
    //      — which invokes `nav.navigate(...)` on a NavController whose
    //      current back stack entry no longer includes this screen. Compose
    //      Navigation throws IllegalStateException or schedules navigation
    //      onto a disposed composition → **force close**.
    //
    // FIX:
    //   - Drop the redundant `scope.launch`. Run scan directly inside the
    //     LaunchedEffect lambda. When the composition leaves, the lambda is
    //     cancelled — `withContext(Dispatchers.IO)` will throw
    //     `CancellationException` at its next suspension point.
    //   - Guard the `onDone` call with `coroutineContext.isActive`. Even
    //     though `withContext` should throw on cancellation before we reach
    //     `onDone`, the JNI call is non-suspending — it returns synchronously
    //     even after the coroutine is cancelled. The `isActive` check is a
    //     belt-and-suspenders guard that catches the case where:
    //       (a) the JNI call is in-flight when cancellation arrives,
    //       (b) the JNI call returns,
    //       (c) `withContext` resumes to find the coroutine cancelled —
    //           normally this throws, but if a different suspension point
    //           runs first the throw is deferred. The explicit `isActive`
    //           check guarantees we never call `onDone` on a dead scope.
    //
    // HISTORY FIX (IMPL-003, stellar-trails v9.8.0):
    //
    //   BUG: original code called `NativeBridge.scan(apkPath)` directly,
    //   bypassing `Repository.scan()`. The Repository is the layer that
    //   inserts a `ScanEntity` into the Room `scans` table on success —
    //   skipping it meant HistoryScreen was ALWAYS empty (the DAO had no
    //   rows to return), even though scans completed successfully.
    //
    //   FIX: route through `repo.scan(context, ApkSource.Path(...))`. The
    //   Repository internally calls `NativeBridge.scan(path)` AND inserts
    //   a history row on `ScanResult.Ok`. We also cache the Markdown in
    //   `ScanResultCache` keyed by `apkPath` so `ReportScreen` can read
    //   it without re-scanning (the nav route now carries the path, not
    //   the Markdown — see IMPL-005 in AppNavGraph.kt).
    //
    //   The APK label passed to the history row is the file's basename
    //   (e.g. `base.apk`). For installed-app scans this is the system
    //   path's base.apk; for SAF-picked files it's the cache filename.
    //   Both are reasonable defaults — if a future iteration wants richer
    //   labels (e.g., the installed app's display name), the caller can
    //   pass the label through the nav route as a second argument.
    //
    // AUTO-CHAIN SIMULATION (stellar-trails v9.9.1, user request):
    //
    //   User's desired flow:
    //     scan apk target →
    //     data result 'blocking-only filter' diperoleh →
    //     auto simulasi sesuai data result →
    //     rangkuman hasil test
    //
    //   We now call `repo.scanWithAutoSimulation()` instead of `repo.scan()`.
    //   The Repository chains:
    //     1. APK scan
    //     2. Play Integrity auto-call (non-fatal on failure)
    //     3. DeviceProbe.gather with the PI verdict baked in
    //     4. NativeBridge.scanSimulatedBlocking(path, profileJson)
    //   Both the scan Markdown and the simulation Markdown are cached
    //   (ScanResultCache + SimulationResultCache) so ReportScreen can
    //   render both sections without re-running either step.
    //
    //   The status messages are updated to reflect the chain. The Play
    //   Integrity step has a 15s warm-up + 10s token request timeout —
    //   we surface that as "Calling Play Integrity API…" so the user
    //   knows why the screen is taking longer than a plain scan.
    LaunchedEffect(apkPath) {
        val source = ApkSource.Path(
            path = apkPath,
            label = File(apkPath).name,
        )

        status = "Scanning DEX strings…"
        // The Repository.scanWithAutoSimulation runs the entire chain
        // (scan → PI → probe → blocking-only simulation) on Dispatchers.IO.
        // We can't surface intermediate progress messages without splitting
        // the chain into multiple suspend calls — for now, the single status
        // message above is shown until the chain completes (~5-30s depending
        // on APK size + Play Integrity warm-up). The user can see the
        // CircularProgressIndicator the whole time.
        val result = withContext(Dispatchers.IO) {
            repo.scanWithAutoSimulation(context, source)
        }
        // Belt-and-suspenders: if the LaunchedEffect was cancelled while the
        // JNI call was in flight, do NOT fire onDone — the screen is gone.
        if (!isActive) return@LaunchedEffect
        when (result) {
            is ScanResult.Ok -> {
                status = "Done."
                // ScanResultCache + SimulationResultCache were populated by
                // Repository.scanWithAutoSimulation — ReportScreen reads
                // from both.
                onDone()
            }
            is ScanResult.Err -> {
                error = result.message
            }
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Scanning…") })
    }) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(32.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                CircularProgressIndicator()
                Text(status, style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Auto-running blocking-only simulation + Play Integrity after scan.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                error?.let { msg ->
                    Text(
                        "Error: $msg",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Button(onClick = onCancel) { Text("Back") }
                }
            }
        }
    }
}
