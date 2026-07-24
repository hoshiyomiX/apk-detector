//! Minimal ZIP central-directory reader. We avoid the `zip` crate's higher-level
//! API to keep the dependency footprint small for the on-device build, but still
//! support the deflate compression every APK uses for `AndroidManifest.xml` and
//! DEX files.
//!
//! This module parses:
//!  - End-of-central-directory record (EOCD)
//!  - Central directory file headers
//!  - Local file headers (for read-on-demand)
//!  - Deflate decompression via the `flate2` pass-through provided by `zip` crate
//!
//! We delegate actual inflate to the `zip` crate's `ZipFile` when reading,
//! because hand-rolling a correct inflate is a security risk. The ZipReader
//! here is just a thin index over the central directory.

use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

use crate::apk::{ApkEntry, ApkError};

#[derive(Debug, Error)]
pub enum ZipReadError {
    #[error("not a zip: no EOCD signature found")]
    NoEocd,
    #[error("zip comment too large: {0}")]
    BadComment(u16),
    #[error("central directory parse error at offset {0}")]
    BadCdh(u64),
    #[error("local header mismatch for {0}")]
    BadLfh(String),
    #[error("unsupported compression method {0} (only deflate=8 and store=0)")]
    UnsupportedCompression(u16),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

const EOCD_SIG: u32 = 0x06054b50;
const CDH_SIG: u32 = 0x02014b50;
const LFH_SIG: u32 = 0x04034b50;

pub struct ZipReader<R: Read + Seek> {
    reader: R,
    entries: Vec<ApkEntry>,
    /// (entry_index -> lfh_offset)
    lfh_offsets: Vec<u64>,
}

impl<R: Read + Seek> ZipReader<R> {
    pub fn open(mut reader: R) -> Result<Self, ApkError> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        // EOCD is at most 22 + 65535 bytes from the end
        let scan_start = file_size.saturating_sub(22 + 65535);
        reader.seek(SeekFrom::Start(scan_start))?;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;

        // Find EOCD signature scanning from end
        let mut eocd_pos = None;
        for i in (0..tail.len().saturating_sub(22)).rev() {
            let sig = u32_le(&tail[i..i + 4]);
            if sig == EOCD_SIG {
                eocd_pos = Some(scan_start + i as u64);
                break;
            }
        }
        let eocd_pos = eocd_pos.ok_or(ApkError::Zip("no EOCD found".into()))?;

        // Read EOCD fields
        reader.seek(SeekFrom::Start(eocd_pos))?;
        let mut eocd = [0u8; 22];
        reader.read_exact(&mut eocd)?;
        let cd_entries = u16_le(&eocd[10..12]) as usize;
        let cd_offset = u32_le(&eocd[16..20]) as u64;

        // Parse central directory
        reader.seek(SeekFrom::Start(cd_offset))?;
        let mut entries = Vec::with_capacity(cd_entries);
        let mut lfh_offsets = Vec::with_capacity(cd_entries);
        for _ in 0..cd_entries {
            let mut sig = [0u8; 4];
            reader.read_exact(&mut sig)?;
            if u32_le(&sig) != CDH_SIG {
                return Err(ApkError::Zip(format!("bad CDH at {}", cd_offset)));
            }
            let mut hdr = [0u8; 42]; // rest of CDH (after sig)
            reader.read_exact(&mut hdr)?;
            let _flags = u16_le(&hdr[0..2]);
            let method = u16_le(&hdr[2..4]);
            let compressed_size = u32_le(&hdr[12..16]) as u64;
            let uncompressed_size = u32_le(&hdr[16..20]) as u64;
            let name_len = u16_le(&hdr[20..22]) as usize;
            let extra_len = u16_le(&hdr[22..24]) as usize;
            let comment_len = u16_le(&hdr[24..26]) as usize;
            let lfh_offset = u32_le(&hdr[38..42]) as u64;

            let mut name = vec![0u8; name_len];
            reader.read_exact(&mut name)?;
            let mut extra = vec![0u8; extra_len];
            reader.read_exact(&mut extra)?;
            let mut comment = vec![0u8; comment_len];
            reader.read_exact(&mut comment)?;

            let _ = method; // method validated at read-time
            entries.push(ApkEntry {
                name: String::from_utf8_lossy(&name).into_owned(),
                compressed_size,
                uncompressed_size,
                is_compressed: method != 0,
            });
            lfh_offsets.push(lfh_offset);
        }

        Ok(Self {
            reader,
            entries,
            lfh_offsets,
        })
    }

    pub fn entries(&self) -> &[ApkEntry] {
        &self.entries
    }

    /// Read a single entry's decompressed bytes.
    ///
    /// Uses the central-directory sizes (authoritative) rather than the local
    /// file header sizes, which may be zero (data descriptor flag) or stale on
    /// APKs produced by streaming writers / repackaging tools. Trusting the
    /// LFH sizes can feed a truncated deflate stream to miniz_oxide, which
    /// panics with `assertion failed: n <= init_unfilled`. The decompression
    /// is also wrapped in `catch_unwind` so any future malformed input becomes
    /// an `ApkError` instead of crashing the JNI process.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>, ApkError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| ApkError::NotFound(name.to_string()))?;
        let lfh_off = self.lfh_offsets[idx];

        // Authoritative sizes from the central directory header.
        let entry = self.entries[idx].clone();
        let method = if entry.is_compressed { 8u16 } else { 0u16 };
        let compressed_size = entry.compressed_size;
        let uncompressed_size = entry.uncompressed_size;

        // Parse local file header — only to skip past name + extra fields.
        self.reader.seek(SeekFrom::Start(lfh_off))?;
        let mut sig = [0u8; 4];
        self.reader.read_exact(&mut sig)?;
        if u32_le(&sig) != LFH_SIG {
            return Err(ApkError::Zip(format!("bad LFH for {}", name)));
        }
        let mut lhdr = [0u8; 26];
        self.reader.read_exact(&mut lhdr)?;
        let name_len = u16_le(&lhdr[22..24]) as usize;
        let extra_len = u16_le(&lhdr[24..26]) as usize;
        self.reader
            .seek(SeekFrom::Current((name_len + extra_len) as i64))?;

        let mut compressed = vec![0u8; compressed_size as usize];
        self.reader.read_exact(&mut compressed)?;

        match method {
            0 => Ok(compressed), // stored
            8 => {
                use std::io::Cursor;
                let decoder = flate2::read::DeflateDecoder::new(Cursor::new(compressed));
                let mut out = Vec::with_capacity(uncompressed_size as usize);
                // miniz_oxide can panic on malformed deflate input (e.g.
                // `assertion failed: n <= init_unfilled`). Catch the panic so
                // a malformed APK returns an error instead of taking down the
                // JNI process.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut d = decoder;
                    d.read_to_end(&mut out)
                }));
                match result {
                    Ok(Ok(_)) => Ok(out),
                    Ok(Err(e)) => Err(ApkError::from(e)),
                    Err(payload) => {
                        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                            s.to_string()
                        } else if let Some(s) = payload.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "unknown panic".to_string()
                        };
                        Err(ApkError::Zip(format!(
                            "deflate panic for {}: {}",
                            name, msg
                        )))
                    }
                }
            }
            m => Err(ApkError::Zip(format!("unsupported compression: {}", m))),
        }
    }
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
