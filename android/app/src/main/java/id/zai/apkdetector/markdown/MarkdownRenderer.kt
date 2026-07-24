package id.zai.apkdetector.markdown

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Minimal Markdown renderer — handles just enough syntax to display
 * APK Detector reports without pulling a third-party Markdown library.
 *
 * Supported:
 *   - `# H1`, `## H2`, `### H3`
 *   - `**bold**`
 *   - `` `code` ``
 *   - `- bullet list item`
 *   - `| table | row |`  (simple two-column rendering)
 *   - `_italic_`
 *   - blank-line-separated paragraphs
 *
 * Not supported (rendered as plain text):
 *   - images, links (we strip the URL syntax)
 *   - nested formatting
 *   - code blocks (```)
 */
@Composable
fun MarkdownRenderer(markdown: String, modifier: Modifier = Modifier) {
    val blocks = remember(markdown) { parseBlocks(markdown) }
    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        blocks.forEach { block -> renderBlock(block) }
    }
}

private sealed class Block {
    data class Heading(val level: Int, val text: String) : Block()
    data class Paragraph(val text: String) : Block()
    data class Bullet(val items: List<String>) : Block()
    data class Table(val header: List<String>, val rows: List<List<String>>) : Block()
    data class Code(val text: String) : Block()
}

private fun parseBlocks(md: String): List<Block> {
    val out = mutableListOf<Block>()
    val lines = md.lines()
    var i = 0
    while (i < lines.size) {
        val line = lines[i]
        when {
            line.startsWith("### ") -> out += Block.Heading(3, line.drop(4))
            line.startsWith("## ") -> out += Block.Heading(2, line.drop(3))
            line.startsWith("# ") -> out += Block.Heading(1, line.drop(2))
            line.startsWith("- ") -> {
                val items = mutableListOf<String>()
                while (i < lines.size && lines[i].startsWith("- ")) {
                    items += lines[i].drop(2)
                    i += 1
                }
                out += Block.Bullet(items)
                continue
            }
            line.startsWith("|") && line.endsWith("|") -> {
                val header = splitRow(line)
                i += 1
                // Skip separator row like |---|---:|
                if (i < lines.size && lines[i].matches(Regex("^\\|[-\\s:|]+\\|$"))) i += 1
                val rows = mutableListOf<List<String>>()
                while (i < lines.size && lines[i].startsWith("|") && lines[i].endsWith("|")) {
                    rows += splitRow(lines[i])
                    i += 1
                }
                out += Block.Table(header, rows)
                continue
            }
            line.isBlank() -> { /* skip */ }
            else -> {
                val sb = StringBuilder(line)
                i += 1
                while (i < lines.size && lines[i].isNotBlank() && !isBlockStart(lines[i])) {
                    sb.append('\n').append(lines[i])
                    i += 1
                }
                out += Block.Paragraph(sb.toString())
                continue
            }
        }
        i += 1
    }
    return out
}

private fun isBlockStart(line: String) = when {
    line.startsWith("# ") || line.startsWith("## ") || line.startsWith("### ") -> true
    line.startsWith("- ") -> true
    line.startsWith("|") -> true
    else -> false
}

private fun splitRow(line: String): List<String> =
    line.trim('|').split('|').map { it.trim() }

@Composable
private fun renderBlock(block: Block) {
    when (block) {
        is Block.Heading -> {
            val style = when (block.level) {
                1 -> MaterialTheme.typography.headlineSmall
                2 -> MaterialTheme.typography.titleLarge
                else -> MaterialTheme.typography.titleMedium
            }
            Text(
                text = stripMd(block.text),
                style = style,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        is Block.Paragraph -> {
            Text(
                text = stripMd(block.text),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        is Block.Bullet -> {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                block.items.forEach { item ->
                    Row {
                        Text("•  ", color = MaterialTheme.colorScheme.primary)
                        Text(stripMd(item), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        is Block.Table -> {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Row(Modifier.fillMaxWidth()) {
                    block.header.forEach { h ->
                        Text(
                            h,
                            modifier = Modifier.weight(1f).padding(4.dp),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
                block.rows.forEach { row ->
                    Row(Modifier.fillMaxWidth()) {
                        row.forEach { cell ->
                            Text(
                                stripMd(cell),
                                modifier = Modifier.weight(1f).padding(4.dp),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
        }
        is Block.Code -> {
            Text(
                text = block.text,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(8.dp),
            )
        }
    }
}

/** Strip basic Markdown inline syntax (`**bold**`, `` `code` ``, `_italic_`). */
private fun stripMd(s: String): String {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        when {
            s.startsWith("**", i) -> { i += 2 /* skip; we don't preserve bold in plain Text */ }
            s.startsWith("`", i) -> { i += 1 }
            s.startsWith("_", i) && (i == 0 || !s[i - 1].isLetterOrDigit()) -> { i += 1 }
            else -> { sb.append(s[i]); i += 1 }
        }
    }
    return sb.toString()
}
