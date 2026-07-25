package id.zai.apkdetector.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.data.NativeBridge
import id.zai.apkdetector.data.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanProgressScreen(
    apkPath: String,
    onDone: (String) -> Unit,
    onCancel: () -> Unit,
) {
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
    LaunchedEffect(apkPath) {
        status = "Scanning DEX strings…"
        val result = withContext(Dispatchers.IO) { NativeBridge.scan(apkPath) }
        // Belt-and-suspenders: if the LaunchedEffect was cancelled while the
        // JNI call was in flight, do NOT fire onDone — the screen is gone.
        if (!isActive) return@LaunchedEffect
        when (result) {
            is ScanResult.Ok -> {
                status = "Done."
                onDone(result.markdown)
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
