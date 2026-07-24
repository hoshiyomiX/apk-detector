package id.zai.apkdetector.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.zai.apkdetector.ApkDetectorApp
import id.zai.apkdetector.data.ScanEntity
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(onBack: () -> Unit) {
    val repo = remember { ApkDetectorApp.get().repository }
    val scope = rememberCoroutineScope()
    var items by remember { mutableStateOf<List<ScanEntity>>(emptyList()) }

    LaunchedEffect(Unit) {
        items = repo.history()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan history") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        scope.launch {
                            repo.clearHistory()
                            items = emptyList()
                        }
                    }) {
                        Icon(Icons.Default.Delete, contentDescription = "Clear")
                    }
                },
            )
        },
    ) { padding ->
        if (items.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text(
                    "No scans yet. Pick an APK from the home screen to begin.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(vertical = 12.dp),
            ) {
                items(items) { item ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(item.apkLabel, style = MaterialTheme.typography.titleSmall)
                            Text(
                                java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                                    .format(java.util.Date(item.createdAt)),
                                style = MaterialTheme.typography.labelSmall,
                            )
                            Text(
                                item.apkPath,
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 2,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            )
                            // Show first 200 chars of markdown as a preview
                            val preview = item.markdown.take(200)
                            Text(
                                preview,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                                modifier = Modifier.padding(top = 4.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}
