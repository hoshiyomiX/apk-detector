//! Minimal DEX string-table reader.
//!
//! We don't parse the full DEX bytecode — only the string pool, which contains
//! every literal referenced by the bytecode (class names, method names, and
//! crucially the strings used in detection checks like `"su"`, `"magisk"`,
//! `"/system/xbin/su"`, `"frida-server"`, etc.).
//!
//! Static detection works by substring-matching these strings against the
//! detection rules in `signatures/`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DexError {
    #[error("not a dex file: bad magic")]
    BadMagic,
    #[error("truncated at offset {0}")]
    Truncated(usize),
    #[error("unsupported dex version: {0:?}")]
    UnsupportedVersion([u8; 3]),
}

const DEX_MAGIC: [u8; 4] = *b"dex\n";

/// DEX string table — owns all decoded strings.
#[derive(Debug, Clone)]
pub struct DexStringTable {
    pub strings: Vec<String>,
}

impl DexStringTable {
    /// Parse a single DEX file's string table.
    pub fn parse(bytes: &[u8]) -> Result<Self, DexError> {
        if bytes.len() < 0x70 {
            return Err(DexError::Truncated(bytes.len()));
        }
        if &bytes[0..4] != DEX_MAGIC {
            return Err(DexError::BadMagic);
        }
        // bytes[4..7] = version "035", "037", "038", "039", "040"
        // We accept any 3-byte version.

        // DEX header layout (offsets of interest):
        //   +0x38 string_ids_size (u32)
        //   +0x3C string_ids_off   (u32)
        //   +0x40 type_ids_size
        //   ...
        let string_ids_size = u32_le(&bytes[0x38..0x3C]) as usize;
        let string_ids_off = u32_le(&bytes[0x3C..0x40]) as usize;

        // string_ids is an array of u32 offsets (one per string), each pointing
        // to a `string_data_item` which begins with a ULEB128 byte-length followed
        // by the UTF-8 bytes (no NUL terminator in our reading — the next string_data_item
        // begins after the ULEB128 + length bytes; in practice there IS a NUL terminator
        // after the UTF-8 bytes, which we don't need to read).
        let mut out = Vec::with_capacity(string_ids_size);
        for i in 0..string_ids_size {
            let p = string_ids_off + i * 4;
            if p + 4 > bytes.len() {
                return Err(DexError::Truncated(p + 4));
            }
            let data_off = u32_le(&bytes[p..p + 4]) as usize;
            if data_off >= bytes.len() {
                continue; // corrupt entry — skip
            }
            let (len, header_n) = uleb128(&bytes, data_off)?;
            let str_start = data_off + header_n;
            let str_end = str_start + len;
            if str_end > bytes.len() {
                continue;
            }
            // DEX uses MUTF-8 which is byte-compatible with UTF-8 for ASCII; for
            // non-ASCII it differs but our detection patterns are all ASCII.
            let s = String::from_utf8_lossy(&bytes[str_start..str_end]).into_owned();
            out.push(s);
        }
        Ok(Self { strings: out })
    }

    /// Scan all strings for ones containing `needle` (case-sensitive substring).
    pub fn find_containing(&self, needle: &str) -> Vec<&str> {
        self.strings.iter()
            .filter_map(|s| if s.contains(needle) { Some(s.as_str()) } else { None })
            .collect()
    }
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode a ULEB128 at `p`. Returns (value, bytes_consumed).
fn uleb128(b: &[u8], p: usize) -> Result<(usize, usize), DexError> {
    let mut result = 0usize;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        if p + i >= b.len() {
            return Err(DexError::Truncated(p + i));
        }
        let byte = b[p + i];
        result |= ((byte & 0x7f) as usize) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DexError::Truncated(p + i));
        }
    }
    Ok((result, i))
}
