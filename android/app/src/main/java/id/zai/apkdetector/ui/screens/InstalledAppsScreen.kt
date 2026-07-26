package id.zai.apkdetector.ui.screens

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Screen that lists installed apps via PackageManager and lets the user
 * pick one to scan. This is the "better scanning approach for installed
 * APKs" the user requested (Task 3): instead of only scanning APK files
 * via SAF picker, the user can now scan ANY installed app by tapping it.
 *
 * ## Why this is the right approach
 *
 * - **No file copying**: `applicationInfo.sourceDir` is a real filesystem
 *   path that the Rust `scanApk` JNI export can read directly. No need to
 *   copy the APK to cache first (unlike the SAF picker flow, which must
 *   copy content:// URIs to a real file).
 * - **User-friendly**: user sees app icons + labels (not opaque filenames).
 * - **Comprehensive**: lists ALL installed packages (system + user) via
 *   `QUERY_ALL_PACKAGES` permission. User can scan any app including
 *   pre-installed banking apps.
 * - **Split-APK aware**: for apps with split APKs (base.apk + config
 *   splits), we scan `sourceDir` which points to base.apk — the defense
 *   mechanisms always live in base. Splits only carry resources/arch libs.
 *
 * ## Threading
 *
 * `PackageManager.getInstalledPackages` is a synchronous IPC call that can
 * take 200-500ms on a mid-range device with ~150 installed apps. We call
 * it on `Dispatchers.IO` from a `LaunchedEffect` to avoid blocking the
 * main thread.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InstalledAppsScreen(
    onScan: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val packageManager = context.packageManager

    // List of installed apps, loaded async on first composition.
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var searchQuery by remember { mutableStateOf("") }

    // Load installed apps on first composition. We sort by label (alphabetical)
    // and filter out apps without a sourceDir (which can happen for system
    // apps that have been uninstalled but left stub entries).
    LaunchedEffect(Unit) {
        loading = true
        apps = withContext(Dispatchers.IO) {
            val flags = PackageManager.GET_META_DATA
            val packages = packageManager.getInstalledPackages(flags)
            packages.mapNotNull { pkg ->
                val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                val sourceDir = appInfo.sourceDir ?: return@mapNotNull null
                if (sourceDir.isEmpty()) return@mapNotNull null
                val label = packageManager.getApplicationLabel(appInfo).toString()
                InstalledApp(
                    packageName = pkg.packageName,
                    label = label,
                    sourceDir = sourceDir,
                    isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    versionName = pkg.versionName ?: "",
                    icon = try {
                        packageManager.getApplicationIcon(appInfo)
                    } catch (_: Throwable) {
                        null
                    },
                )
            }.sortedBy { it.label.lowercase() }
        }
        loading = false
    }

    // Filter by search query (case-insensitive on label + packageName).
    val filteredApps = remember(apps, searchQuery) {
        if (searchQuery.isBlank()) apps
        else apps.filter {
            it.label.contains(searchQuery, ignoreCase = true) ||
                it.packageName.contains(searchQuery, ignoreCase = true)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Installed apps (${apps.size})") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            // Search bar — filter by label or package name.
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                placeholder = { Text("Search by app name or package") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
            )

            if (loading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator()
                        Text("Loading installed apps…", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                return@Scaffold
            }

            if (filteredApps.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (searchQuery.isBlank()) "No installed apps found."
                        else "No apps match \"$searchQuery\".",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                return@Scaffold
            }

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(filteredApps, key = { it.packageName }) { app ->
                    InstalledAppRow(app = app, onClick = { onScan(app.sourceDir) })
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun InstalledAppRow(app: InstalledApp, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // App icon — fall back to a generic icon if the icon fails to load.
        if (app.icon != null) {
            // android.graphics.drawable.Drawable → ImageBitmap via asImageBitmap()
            // We render it at 40dp to keep the row compact.
            val drawable = app.icon
            val bitmap = remember(drawable) {
                val bmp = android.graphics.Bitmap.createBitmap(40, 40, android.graphics.Bitmap.Config.ARGB_8888)
                val canvas = android.graphics.Canvas(bmp)
                drawable.setBounds(0, 0, 40, 40)
                drawable.draw(canvas)
                bmp.asImageBitmap()
            }
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
            )
        } else {
            Icon(
                Icons.Default.Apps,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
            )
        }

        Column(modifier = Modifier.weight(1f)) {
            Text(
                app.label,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
            )
            Text(
                app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
            Text(
                if (app.isSystem) "system • v${app.versionName}" else "v${app.versionName}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * One installed app entry. `sourceDir` is the real filesystem path to the
 * base.apk file — passed directly to `NativeBridge.scan(path)`.
 */
private data class InstalledApp(
    val packageName: String,
    val label: String,
    val sourceDir: String,
    val isSystem: Boolean,
    val versionName: String,
    val icon: android.graphics.drawable.Drawable?,
)
