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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanProgressScreen(
    apkPath: String,
    onDone: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("Opening APK…") }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(apkPath) {
        scope.launch {
            status = "Scanning DEX strings…"
            val result = withContext(Dispatchers.IO) { NativeBridge.scan(apkPath) }
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
