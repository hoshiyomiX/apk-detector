package id.zai.apkdetector.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import id.zai.apkdetector.ui.screens.DiffScreen
import id.zai.apkdetector.ui.screens.HistoryScreen
import id.zai.apkdetector.ui.screens.PickerScreen
import id.zai.apkdetector.ui.screens.ReportScreen
import id.zai.apkdetector.ui.screens.ScanProgressScreen

object Routes {
    const val PICKER = "picker"
    const val SCAN = "scan/{path}"
    const val REPORT = "report/{markdown}"
    const val DIFF = "diff"
    const val HISTORY = "history"
}

@Composable
fun AppNavGraph() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = Routes.PICKER) {
        composable(Routes.PICKER) {
            PickerScreen(
                onScan = { path -> nav.navigate("scan/${encode(path)}") },
                onDiff = { nav.navigate(Routes.DIFF) },
                onHistory = { nav.navigate(Routes.HISTORY) },
            )
        }
        composable(Routes.SCAN) { backStackEntry ->
            val path = decode(backStackEntry.arguments?.getString("path").orEmpty())
            ScanProgressScreen(
                apkPath = path,
                onDone = { markdown -> nav.navigate("report/${encode(markdown)}") {
                    popUpTo(Routes.PICKER)
                } },
                onCancel = { nav.popBackStack() },
            )
        }
        composable(Routes.REPORT) { backStackEntry ->
            val markdown = decode(backStackEntry.arguments?.getString("markdown").orEmpty())
            ReportScreen(
                markdown = markdown,
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.DIFF) {
            DiffScreen(onBack = { nav.popBackStack() })
        }
        composable(Routes.HISTORY) {
            HistoryScreen(onBack = { nav.popBackStack() })
        }
    }
}

// URL-encode helpers for path/Markdown args (they can contain slashes, hashes, etc.)
private fun encode(s: String): String =
    java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

private fun decode(s: String): String =
    java.net.URLDecoder.decode(s, "UTF-8")
