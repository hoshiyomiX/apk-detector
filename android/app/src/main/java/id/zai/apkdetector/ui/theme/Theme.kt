package id.zai.apkdetector.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Dark = darkColorScheme(
    primary = Color(0xFF82B1FF),
    onPrimary = Color.Black,
    secondary = Color(0xFFFF80AB),
    background = Color(0xFF101010),
    surface = Color(0xFF1A1A1A),
)

private val Light = lightColorScheme(
    primary = Color(0xFF1A56DB),
    secondary = Color(0xFFB71C5C),
    background = Color(0xFFFAFAFA),
    surface = Color(0xFFFFFFFF),
)

@Composable
fun APKDetectorTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) Dark else Light,
        content = content,
    )
}
