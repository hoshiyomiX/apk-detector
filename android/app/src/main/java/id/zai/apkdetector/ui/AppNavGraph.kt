package id.zai.apkdetector.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import id.zai.apkdetector.ui.screens.DeviceScanScreen
import id.zai.apkdetector.ui.screens.HistoryScreen
import id.zai.apkdetector.ui.screens.InstalledAppsScreen
import id.zai.apkdetector.ui.screens.PickerScreen
import id.zai.apkdetector.ui.screens.ReportScreen
import id.zai.apkdetector.ui.screens.ScanProgressScreen

object Routes {
    const val PICKER = "picker"
    const val SCAN = "scan/{path}"
    const val REPORT = "report/{path}"
    const val HISTORY = "history"
    const val INSTALLED_APPS = "installed_apps"
    const val DEVICE_SCAN = "device_scan"
}

@Composable
fun AppNavGraph() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = Routes.PICKER) {
        composable(Routes.PICKER) {
            PickerScreen(
                onScan = { path -> nav.navigate("scan/${encode(path)}") },
                onHistory = { nav.navigate(Routes.HISTORY) },
                onInstalledApps = { nav.navigate(Routes.INSTALLED_APPS) },
                onDeviceScan = { nav.navigate(Routes.DEVICE_SCAN) },
            )
        }
        composable(Routes.INSTALLED_APPS) {
            InstalledAppsScreen(
                onScan = { path -> nav.navigate("scan/${encode(path)}") },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.DEVICE_SCAN) {
            DeviceScanScreen(
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.SCAN) { backStackEntry ->
            val path = decode(backStackEntry.arguments?.getString("path").orEmpty())
            ScanProgressScreen(
                apkPath = path,
                // IMPL-005 (stellar-trails v9.8.0):
                //
                //   Previously `onDone` received the Markdown and the
                //   REPORT route carried it as a URL-encoded argument.
                //   That was the root cause of the `%J` crash (IMPL-001):
                //   Navigation Compose's `Uri.decode()` throws on malformed
                //   `%XX` escapes, and the Markdown contains literal `%`
                //   whenever the APK path does.
                //
                //   Now `onDone` takes no arguments — `ScanProgressScreen`
                //   caches the Markdown in `ScanResultCache` keyed by the
                //   APK path, and we navigate with only the (short,
                //   URL-safe) path. `ReportScreen` reads the Markdown back
                //   from the cache (or re-scans on cache miss).
                onDone = { nav.navigate("report/${encode(path)}") {
                    popUpTo(Routes.PICKER)
                } },
                onCancel = { nav.popBackStack() },
            )
        }
        composable(Routes.REPORT) { backStackEntry ->
            val path = decode(backStackEntry.arguments?.getString("path").orEmpty())
            ReportScreen(
                apkPath = path,
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.HISTORY) {
            HistoryScreen(onBack = { nav.popBackStack() })
        }
    }
}

// URL-encode helpers for path args (paths can contain slashes, hashes, etc.).
private fun encode(s: String): String =
    java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

// Defensive URL-decode for path args.
//
// CRASH FIX (IMPL-001, stellar-trails v9.8.0):
//
//   Bug: `URLDecoder.decode(s, "UTF-8")` throws `IllegalArgumentException`
//   ("Illegal hex characters in escape (%) pattern") when the input contains
//   a literal `%` that is NOT part of a valid `%XX` escape.
//
//   Root cause: Navigation Compose 2.8.1 saves the back stack (including
//   route arguments) to the Android Bundle on process death. On restoration,
//   the saved route string can be either (a) truncated mid-`%XX` by the
//   Bundle size cap, or (b) pre-decoded once by Nav's internal `Uri.decode()`
//   before our `decode()` runs. Either path leaves a literal `%` in the
//   input that `URLDecoder.decode` cannot parse, and Compose's `Recomposer`
//   does not catch `IllegalArgumentException` from composable lambdas — so
//   the exception propagates up through `performRecompose` →
//   `Choreographer` → `ActivityThread.main` and the app force-closes.
//
//   Fix: catch `IllegalArgumentException` and return the input unchanged.
//   This is correct because:
//     * If the input was already decoded by Nav, returning it as-is is the
//       right answer (no double-decode).
//     * If the input was truncated mid-escape, returning the truncated form
//       is the best we can do — the UI shows a partial path instead of
//       force-closing. The user can re-pick the APK to get a full path.
//     * If the input was well-formed, the try block returns the decoded
//       string and the catch is never entered.
//
//   As of IMPL-005, the REPORT route carries only the (short, URL-safe)
//   APK path — the Markdown is passed via `ScanResultCache`. This eliminates
//   the truncation case for the REPORT route entirely (paths are typically
//   < 200 chars, well under the Bundle size cap). The defensive catch
//   remains as belt-and-suspenders for the SCAN route and for any future
//   route that carries a path argument.
private fun decode(s: String): String =
    try {
        java.net.URLDecoder.decode(s, "UTF-8")
    } catch (_: IllegalArgumentException) {
        // Malformed % escape — input is either already decoded by Nav,
        // truncated by Bundle size cap, or contains a literal `%`. Return
        // as-is rather than force-closing the app.
        s
    }
