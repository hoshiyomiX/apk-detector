package id.zai.apkdetector.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import id.zai.apkdetector.ui.screens.DiffScreen
import id.zai.apkdetector.ui.screens.HistoryScreen
import id.zai.apkdetector.ui.screens.InstalledAppsScreen
import id.zai.apkdetector.ui.screens.PickerScreen
import id.zai.apkdetector.ui.screens.ReportScreen
import id.zai.apkdetector.ui.screens.ScanProgressScreen

object Routes {
    const val PICKER = "picker"
    const val SCAN = "scan/{path}"
    const val REPORT = "report/{markdown}"
    const val DIFF = "diff"
    const val HISTORY = "history"
    const val INSTALLED_APPS = "installed_apps"
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
                onInstalledApps = { nav.navigate(Routes.INSTALLED_APPS) },
            )
        }
        composable(Routes.INSTALLED_APPS) {
            InstalledAppsScreen(
                onScan = { path -> nav.navigate("scan/${encode(path)}") },
                onBack = { nav.popBackStack() },
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

// Defensive URL-decode for path/Markdown args.
//
// CRASH FIX (IMPL-001, stellar-trails v9.8.0):
//
//   Bug: `URLDecoder.decode(s, "UTF-8")` throws `IllegalArgumentException`
//   ("Illegal hex characters in escape (%) pattern") when the input contains
//   a literal `%` that is NOT part of a valid `%XX` escape. This was observed
//   in production crash logs (bin.kv2.dev/~6a65ed47d9c8790013994061) with the
//   marker `%J` — i.e. a percent sign immediately followed by the letter `J`.
//
//   Root cause: Navigation Compose 2.8.1 saves the back stack (including route
//   arguments) to the Android Bundle on process death. On restoration, the
//   saved route string can be either (a) truncated mid-`%XX` by the Bundle
//   size cap, or (b) pre-decoded once by Nav's internal `Uri.decode()` before
//   our `decode()` runs. Either path leaves a literal `%` in the input that
//   `URLDecoder.decode` cannot parse, and Compose's `Recomposer` does not
//   catch `IllegalArgumentException` from composable lambdas — so the
//   exception propagates up through `performRecompose` → `Choreographer` →
//   `ActivityThread.main` and the app force-closes.
//
//   The marker `%J` specifically points at the REPORT route (4th composable
//   in AppNavGraph, `$1$1$3`), which decodes the markdown argument. The
//   markdown report embeds `apk_path` verbatim (see detector/src/report.rs
//   line 87: `**Target:** \`{apk_path}\``). If the user picked an APK whose
//   path contains a literal `%` — e.g. `/sdcard/50%Jump/app.apk` — or whose
//   installed `sourceDir` contains `%`, the markdown contains `%J` after
//   one round of decoding, and our second `decode()` crashes.
//
//   Fix: catch `IllegalArgumentException` and return the input unchanged.
//   This is correct because:
//     * If the input was already decoded by Nav, returning it as-is is the
//       right answer (no double-decode).
//     * If the input was truncated mid-escape, returning the truncated form
//       is the best we can do — the UI shows a partial report instead of
//       force-closing. The user can re-scan to get a complete report.
//     * If the input was well-formed, the try block returns the decoded
//       string and the catch is never entered.
//
//   Long-term improvement (deferred — out of scope for this fix): stop
//   passing the markdown through the nav route entirely. Use a shared
//   ViewModel with SavedStateHandle, or a singleton cache keyed by a UUID
//   passed through the route. That eliminates the truncation case and
//   removes the size pressure on the Bundle. For now, the defensive catch
//   is the minimal correct fix.
private fun decode(s: String): String =
    try {
        java.net.URLDecoder.decode(s, "UTF-8")
    } catch (_: IllegalArgumentException) {
        // Malformed % escape — input is either already decoded by Nav,
        // truncated by Bundle size cap, or contains a literal `%`. Return
        // as-is rather than force-closing the app.
        s
    }
