//! Minimal ZIP central-directory reader. We avoid the `zip` crate's higher-level
//! API to keep the dependency footprint small for the on-device build, but still
//! support the deflate compression every APK uses for `AndroidManifest.xml` and
//! DEX files.
//!
//! This module parses:
//!  - End-of-central-directory record (EOCD)
//!  - Central directory file headers
//!  - Local file headers (for read-on-demand)
//!  - Deflate decompression via the pure-Rust `inflate` crate
//!
//! We use the `inflate` crate (not `flate2`/`miniz_oxide`) because miniz_oxide
//! has unsafe internals that can SIGSEGV on malformed DEFLATE input — a signal
//! that `std::panic::catch_unwind` cannot intercept, crashing the JNI process.
//! The `inflate` crate is 100% safe Rust and returns `Result` instead of
//! panicking, eliminating the entire failure class.

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
        // EOCD is at most 22 + 65535 bytes from the end (22-byte record +
        // up to 65535-byte comment, per PKWARE APPNOTE.TXT 4.3.16).
        let scan_start = file_size.saturating_sub(22 + 65535);
        reader.seek(SeekFrom::Start(scan_start))?;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;

        // The EOCD record is 22 bytes. Its signature lives at the start of
        // the record, so the signature can sit at any offset `i` where
        // `i + 22 <= tail.len()`. The last valid offset is therefore
        // `tail.len() - 22`, which corresponds to a ZIP file with NO
        // comment (the common case for system APKs and repackaged APKs).
        //
        // We MUST iterate the range inclusively (`0..=last_start`) — using
        // an exclusive upper bound (`0..last_start`) would skip the very
        // last position and miss EOCD for any ZIP without a comment.
        if tail.len() < 22 {
            return Err(ApkError::Zip(format!(
                "no EOCD found (file_size={}, need >=22 bytes for a valid ZIP EOCD; \
                 file too small or truncated)",
                file_size
            )));
        }
        let last_start = tail.len() - 22;
        let mut eocd_pos = None;
        for i in (0..=last_start).rev() {
            let sig = u32_le(&tail[i..i + 4]);
            if sig == EOCD_SIG {
                eocd_pos = Some(scan_start + i as u64);
                break;
            }
        }
        let eocd_pos = eocd_pos.ok_or_else(|| {
            ApkError::Zip(format!(
                "no EOCD found (file_size={}, scanned last {} bytes for signature 0x06054b50; \
                 file may be truncated, corrupt, or not a ZIP)",
                file_size,
                tail.len()
            ))
        })?;

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
    /// LFH sizes can feed a truncated deflate stream to the decompressor.
    ///
    /// Decompression uses the `inflate` crate (pure Rust). Although `inflate`
    /// is mostly safe Rust, it contains `assert!` calls and one `unsafe`
    /// block that CAN panic on certain malformed inputs. We wrap the call in
    /// `std::panic::catch_unwind` as defense-in-depth so a malformed APK
    /// returns an `ApkError` instead of crashing the JNI process. We also
    /// reject empty streams early (CDH compressed_size=0 is almost always a
    /// stale-size artifact from streaming writers).
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
        let _uncompressed_size = entry.uncompressed_size;

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
                // ZIP entries use raw DEFLATE (no zlib header) — use
                // `inflate::inflate_bytes`, NOT `inflate_bytes_zlib`.
                //
                // The `inflate` crate is mostly safe Rust but DOES contain
                // `assert!` calls (lines 215, 236, 654, 656, 661 in its
                // source) and one `unsafe { set_len }` block (line 657).
                // On certain malformed DEFLATE inputs these asserts can fire
                // and panic the JNI process. We wrap the call in
                // `catch_unwind` as defense-in-depth so a malformed APK
                // returns an `ApkError` instead of crashing.
                //
                // We also reject obviously-bogus streams early: a valid
                // DEFLATE stream needs at least 1 byte (the block header).
                // A 0-byte "compressed" entry is almost certainly a CDH/LFH
                // size mismatch and would cause inflate to fail anyway.
                if compressed.is_empty() {
                    return Err(ApkError::Zip(format!(
                        "empty deflate stream for {} (CDH compressed_size=0 — \
                         likely a streaming-writer APK with stale sizes)",
                        name
                    )));
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    inflate::inflate_bytes(&compressed)
                }));
                match result {
                    Ok(Ok(bytes)) => Ok(bytes),
                    Ok(Err(e)) => Err(ApkError::Zip(format!("deflate error for {}: {}", name, e))),
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

#[cfg(test)]
mod tests {
    //! Tests for the EOCD search loop. The original implementation used an
    //! exclusive upper bound (`0..tail.len()-22`) which skipped the very
    //! last valid offset, causing every ZIP file *without* a comment to fail
    //! with "no EOCD found". The fix uses an inclusive range (`0..=N`).

    use super::*;
    use std::io::Cursor;

    /// Build a minimal valid empty ZIP: just the 22-byte EOCD record with
    /// all-zero fields and zero comment. This is the smallest legal ZIP.
    fn empty_zip_no_comment() -> Vec<u8> {
        let mut v = Vec::with_capacity(22);
        v.extend_from_slice(&EOCD_SIG.to_le_bytes()); // signature
        v.extend_from_slice(&0u16.to_le_bytes()); // disk number
        v.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
        v.extend_from_slice(&0u16.to_le_bytes()); // CD entries on this disk
        v.extend_from_slice(&0u16.to_le_bytes()); // total CD entries
        v.extend_from_slice(&0u32.to_le_bytes()); // CD size
        v.extend_from_slice(&0u32.to_le_bytes()); // CD offset
        v.extend_from_slice(&0u16.to_le_bytes()); // comment length
        assert_eq!(v.len(), 22);
        v
    }

    /// An empty ZIP with no comment MUST open successfully. This regression
    /// test fails with the original off-by-one code (loop range was
    /// `0..0` = empty) and passes with the fixed code (loop range is
    /// `0..=0` = `[0]`).
    #[test]
    fn test_open_empty_zip_no_comment() {
        let bytes = empty_zip_no_comment();
        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "empty ZIP (22 bytes, no comment) must open — got: {:?}",
            result.as_ref().err()
        );
        let zip = result.unwrap();
        assert!(zip.entries().is_empty(), "empty ZIP has no entries");
    }

    /// An empty ZIP with a 5-byte comment MUST open successfully. This case
    /// worked even with the original code (because the EOCD sits at offset 0,
    /// which is within the original exclusive range). It's included as a
    /// regression check to make sure the inclusive-range fix didn't break
    /// the with-comment path.
    #[test]
    fn test_open_empty_zip_with_comment() {
        let comment = b"hello";
        let mut bytes = empty_zip_no_comment();
        // Patch comment length field (last 2 bytes of EOCD) to len(comment).
        let len_pos = bytes.len() - 2;
        bytes[len_pos..len_pos + 2].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        bytes.extend_from_slice(comment);
        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "empty ZIP with comment must open — got: {:?}",
            result.as_ref().err()
        );
    }

    /// A file smaller than 22 bytes (the minimum EOCD size) MUST return an
    /// error, not panic. The error message should mention `file_size` so the
    /// user can diagnose truncation.
    #[test]
    fn test_open_too_small_returns_err() {
        let bytes = vec![0u8; 10]; // 10 bytes, way too small
        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(result.is_err(), "10-byte file must error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("file_size=10"),
            "error must mention file_size for diagnostics, got: {}",
            msg
        );
    }

    /// An empty file (0 bytes) MUST return an error, not panic.
    #[test]
    fn test_open_empty_file_returns_err() {
        let bytes: Vec<u8> = Vec::new();
        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(result.is_err(), "empty file must error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("file_size=0"),
            "error must mention file_size=0, got: {}",
            msg
        );
    }
}
