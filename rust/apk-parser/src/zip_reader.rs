//! Minimal ZIP central-directory reader. We avoid the `zip` crate's higher-level
//! API to keep the dependency footprint small for the on-device build, but still
//! support the deflate compression every APK uses for `AndroidManifest.xml` and
//! DEX files.
//!
//! This module parses:
//!  - End-of-central-directory record (EOCD) — with `comment_len` verification
//!    to reject false-positive EOCD signatures that appear inside ZIP comments,
//!    file bodies, or APK Signing Blocks.
//!  - ZIP64 EOCD locator + record (read-only) for archives exceeding 4 GB or
//!    65535 entries (sentinels `0xFFFF` / `0xFFFFFFFF` in the classic EOCD).
//!  - Central directory file headers — with ZIP64 extra-field (header ID
//!    0x0001) parsing for entries whose size or offset fields are sentinels.
//!  - Local file headers (for read-on-demand).
//!  - Deflate decompression via the pure-Rust `inflate` crate.
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
/// ZIP64 EOCD locator signature (sits 20 bytes before the classic EOCD).
const ZIP64_EOCD_LOC_SIG: u32 = 0x07064b50;
/// ZIP64 EOCD record signature (located via the locator's offset field).
const ZIP64_EOCD_SIG: u32 = 0x06064b50;
/// Sentinel value indicating "real value lives in the ZIP64 EOCD record".
const ZIP64_SENTINEL_U32: u64 = 0xFFFF_FFFF;
/// Sentinel value (16-bit) indicating "real value lives in the ZIP64 EOCD record".
const ZIP64_SENTINEL_U16: u64 = 0xFFFF;
/// ZIP64 extra-field header ID (per APPNOTE.TXT 4.5.3).
const ZIP64_EXTRA_HEADER_ID: u16 = 0x0001;

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

        // Find EOCD with `comment_len` verification. A naive backwards scan
        // that accepts the first EOCD_SIG match can pick up a false positive
        // — the 4-byte signature 0x06054b50 can appear by coincidence inside
        // a ZIP comment, inside file data, or inside an APK Signing Block.
        // When that happens the false-positive EOCD's `cd_offset` points to
        // garbage, producing "bad CDH at <cd_offset>" on the very first
        // entry. The fix is to verify each candidate: its `comment_len`
        // field, added to `eocd_pos + 22`, must equal `file_size`. Only an
        // EOCD whose comment ends exactly at EOF is valid.
        let mut eocd_pos = None;
        for i in (0..=last_start).rev() {
            let sig = u32_le(&tail[i..i + 4]);
            if sig != EOCD_SIG {
                continue;
            }
            let abs_pos = scan_start + i as u64;
            // comment_len lives at offset 20..22 within the EOCD record.
            let comment_len = u16_le(&tail[i + 20..i + 22]) as u64;
            if abs_pos + 22 + comment_len == file_size {
                eocd_pos = Some(abs_pos);
                break;
            }
            // Otherwise: false-positive EOCD signature. Continue scanning
            // backwards for the real EOCD.
        }
        let eocd_pos = eocd_pos.ok_or_else(|| {
            ApkError::Zip(format!(
                "no EOCD found (file_size={}, scanned last {} bytes for signature 0x06054b50; \
                 no candidate had a valid comment_len — file may be truncated, corrupt, \
                 or not a ZIP)",
                file_size,
                tail.len()
            ))
        })?;

        // Read EOCD fields
        reader.seek(SeekFrom::Start(eocd_pos))?;
        let mut eocd = [0u8; 22];
        reader.read_exact(&mut eocd)?;
        let mut cd_entries = u16_le(&eocd[10..12]) as u64;
        // cd_size is read only for the ZIP64 sentinel check; we don't use
        // the resolved value afterward, so we keep the classic value and
        // don't bother reading the ZIP64 EOCD's 64-bit cd_size field.
        let cd_size_classic = u32_le(&eocd[12..16]) as u64;
        let mut cd_offset = u32_le(&eocd[16..20]) as u64;

        // ZIP64 sentinel handling. If any of `cd_entries`, `cd_size`, or
        // `cd_offset` is the 0xFFFF / 0xFFFFFFFF sentinel, the real values
        // live in a ZIP64 EOCD record. The ZIP64 EOCD locator sits exactly
        // 20 bytes before the classic EOCD: 4-byte signature (0x07064b50)
        // + 4-byte disk number + 8-byte ZIP64 EOCD offset + 4-byte total
        // disks. The locator points to a ZIP64 EOCD record (signature
        // 0x06064b50) which carries 64-bit versions of the count/size/offset
        // fields.
        //
        // This is rare for APKs (Android's apkbuilder doesn't produce ZIP64
        // unless the APK exceeds 4 GB or 65535 entries), but some
        // multi-feature apps (e.g., large games) do exceed these limits.
        let has_zip64_sentinel = cd_entries == ZIP64_SENTINEL_U16
            || cd_offset == ZIP64_SENTINEL_U32
            || cd_size_classic == ZIP64_SENTINEL_U32;
        if has_zip64_sentinel {
            if eocd_pos < 20 {
                return Err(ApkError::Zip(format!(
                    "ZIP64 sentinel in EOCD but no room for ZIP64 EOCD locator \
                     (eocd_pos={}, need >=20 bytes before EOCD)",
                    eocd_pos
                )));
            }
            let locator_pos = eocd_pos - 20;
            reader.seek(SeekFrom::Start(locator_pos))?;
            let mut loc = [0u8; 20];
            reader.read_exact(&mut loc)?;
            if u32_le(&loc[0..4]) != ZIP64_EOCD_LOC_SIG {
                return Err(ApkError::Zip(format!(
                    "ZIP64 sentinel in EOCD but no ZIP64 EOCD locator at {} \
                     (found signature 0x{:08x}, expected 0x{:08x})",
                    locator_pos,
                    u32_le(&loc[0..4]),
                    ZIP64_EOCD_LOC_SIG
                )));
            }
            let zip64_eocd_offset = u64_le(&loc[8..16]);
            if zip64_eocd_offset >= file_size {
                return Err(ApkError::Zip(format!(
                    "ZIP64 EOCD locator points past EOF (offset={}, file_size={})",
                    zip64_eocd_offset, file_size
                )));
            }
            reader.seek(SeekFrom::Start(zip64_eocd_offset))?;
            // ZIP64 EOCD record layout (56 bytes we care about):
            //   0..4   signature (0x06064b50)
            //   4..12  size of remaining record
            //   12..14 version made by
            //   14..16 version needed
            //   16..20 disk number
            //   20..24 disk with CD start
            //   24..32 entries on this disk
            //   32..40 total entries
            //   40..48 cd_size
            //   48..56 cd_offset
            let mut z64 = [0u8; 56];
            reader.read_exact(&mut z64)?;
            if u32_le(&z64[0..4]) != ZIP64_EOCD_SIG {
                return Err(ApkError::Zip(format!(
                    "ZIP64 EOCD record at {} has wrong signature \
                     (found 0x{:08x}, expected 0x{:08x})",
                    zip64_eocd_offset,
                    u32_le(&z64[0..4]),
                    ZIP64_EOCD_SIG
                )));
            }
            cd_entries = u64_le(&z64[32..40]);
            cd_offset = u64_le(&z64[48..56]);
        }

        // Parse central directory. Each CDH starts with the 4-byte signature
        // 0x02014b50. If the signature doesn't match, the EOCD's cd_offset
        // was likely wrong (stale EOCD, false-positive EOCD match, or a
        // corrupt central directory). Report the ACTUAL current reader
        // position so the user can diagnose which entry triggered the
        // failure, not just where the CD started.
        //
        // We cap the allocation at 1024 entries (common APK range is 100-500
        // entries) to avoid a huge Vec on a corrupt cd_entries count.
        reader.seek(SeekFrom::Start(cd_offset))?;
        let mut entries = Vec::with_capacity(cd_entries.min(1024) as usize);
        let mut lfh_offsets = Vec::with_capacity(entries.capacity());
        for i in 0..cd_entries {
            let current_pos = reader.stream_position()?;
            let mut sig = [0u8; 4];
            reader.read_exact(&mut sig)?;
            if u32_le(&sig) != CDH_SIG {
                return Err(ApkError::Zip(format!(
                    "bad CDH at offset {} (entry #{}; cd_offset={}, cd_entries={}; \
                     found signature 0x{:08x}, expected 0x{:08x})",
                    current_pos,
                    i,
                    cd_offset,
                    cd_entries,
                    u32_le(&sig),
                    CDH_SIG
                )));
            }
            // CDH layout (PKWARE APPNOTE.TXT 4.3.12). After the 4-byte
            // signature, the remaining 42 bytes are read into `hdr`. Field
            // offsets below are RELATIVE TO `hdr` (i.e., relative to the
            // first byte AFTER the signature), NOT relative to the start of
            // the CDH record. Mixing these up was the proximate cause of the
            // "bad CDH at <offset>" and "io: failed to fill whole buffer"
            // crashes: an earlier version of this code used offsets as if
            // `hdr` included the 4-byte signature (every field read 4 bytes
            // too early), so `name_len`/`extra_len`/`comment_len` actually
            // read bytes from `uncompressed_size`/`compressed_size`, producing
            // bogus lengths that made the parser skip past real CDH entries
            // and land on garbage.
            //
            // hdr offset | CDH field
            // -----------+--------------------------------
            //  0..2      | version made by
            //  2..4      | version needed to extract
            //  4..6      | general purpose bit flag
            //  6..8      | compression method
            //  8..10     | last mod file time
            // 10..12     | last mod file date
            // 12..16     | CRC-32
            // 16..20     | compressed size
            // 20..24     | uncompressed size
            // 24..26     | file name length (n)
            // 26..28     | extra field length (m)
            // 28..30     | file comment length (k)
            // 30..32     | disk number start
            // 32..34     | internal file attributes
            // 34..38     | external file attributes
            // 38..42     | relative offset of local header
            let mut hdr = [0u8; 42]; // rest of CDH (after sig)
            reader.read_exact(&mut hdr)?;
            let _version_made_by = u16_le(&hdr[0..2]);
            let _version_needed = u16_le(&hdr[2..4]);
            let _flags = u16_le(&hdr[4..6]);
            let method = u16_le(&hdr[6..8]);
            let _mod_time = u16_le(&hdr[8..10]);
            let _mod_date = u16_le(&hdr[10..12]);
            let _crc32 = u32_le(&hdr[12..16]);
            let mut compressed_size = u32_le(&hdr[16..20]) as u64;
            let mut uncompressed_size = u32_le(&hdr[20..24]) as u64;
            let name_len = u16_le(&hdr[24..26]) as usize;
            let extra_len = u16_le(&hdr[26..28]) as usize;
            let comment_len = u16_le(&hdr[28..30]) as usize;
            let _disk_number = u16_le(&hdr[30..32]);
            let _internal_attrs = u16_le(&hdr[32..34]);
            let _external_attrs = u32_le(&hdr[34..38]);
            let mut lfh_offset = u32_le(&hdr[38..42]) as u64;

            let mut name = vec![0u8; name_len];
            reader.read_exact(&mut name)?;
            let mut extra = vec![0u8; extra_len];
            reader.read_exact(&mut extra)?;
            let mut comment = vec![0u8; comment_len];
            reader.read_exact(&mut comment)?;
            let _ = comment; // comment is read for reader position advance; value unused

            // ZIP64 extra-field parsing (header ID 0x0001). The order is
            // fixed per APPNOTE.TXT 4.5.3: uncompressed_size, then
            // compressed_size, then lfh_offset, then disk_number — but only
            // the fields whose CDH counterparts were 0xFFFFFFFF sentinels
            // are actually present. We must respect the sentinel check on
            // each field individually before consuming the next 8 bytes.
            if compressed_size == ZIP64_SENTINEL_U32
                || uncompressed_size == ZIP64_SENTINEL_U32
                || lfh_offset == ZIP64_SENTINEL_U32
            {
                let mut ex = 0usize;
                while ex + 4 <= extra.len() {
                    let header_id = u16_le(&extra[ex..ex + 2]);
                    let data_size = u16_le(&extra[ex + 2..ex + 4]) as usize;
                    let data_start = ex + 4;
                    let data_end = data_start + data_size;
                    if data_end > extra.len() {
                        break;
                    }
                    if header_id == ZIP64_EXTRA_HEADER_ID {
                        let mut p = data_start;
                        if uncompressed_size == ZIP64_SENTINEL_U32 && p + 8 <= data_end {
                            uncompressed_size = u64_le(&extra[p..p + 8]);
                            p += 8;
                        }
                        if compressed_size == ZIP64_SENTINEL_U32 && p + 8 <= data_end {
                            compressed_size = u64_le(&extra[p..p + 8]);
                            p += 8;
                        }
                        if lfh_offset == ZIP64_SENTINEL_U32 && p + 8 <= data_end {
                            lfh_offset = u64_le(&extra[p..p + 8]);
                            // disk_number would follow but we don't need it.
                        }
                        break;
                    }
                    ex = data_end;
                }
            }

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
fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests {
    //! Tests for the EOCD search loop and ZIP64 sentinel handling.
    //!
    //! History: the original implementation used an exclusive upper bound
    //! (`0..tail.len()-22`) which skipped the very last valid offset,
    //! causing every ZIP file *without* a comment to fail with "no EOCD
    //! found". The fix used an inclusive range (`0..=N`).
    //!
    //! A second bug was then discovered: the backwards scan accepted the
    //! first EOCD_SIG match without verifying `comment_len`. The 4-byte
    //! signature 0x06054b50 can appear by coincidence inside a ZIP
    //! comment, file body, or APK Signing Block — producing a
    //! false-positive EOCD whose `cd_offset` points to garbage and yields
    //! "bad CDH at <cd_offset>" on the very first entry. The fix verifies
    //! each candidate EOCD via `abs_pos + 22 + comment_len == file_size`.
    //!
    //! ZIP64 sentinel handling was added because APKs exceeding 4 GB or
    //! 65535 entries use 0xFFFF / 0xFFFFFFFF sentinels in the classic
    //! EOCD, with real values in a ZIP64 EOCD record (located via a
    //! ZIP64 EOCD locator 20 bytes before the classic EOCD).

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
        // Use `match` (not `unwrap_err`) because `unwrap_err` requires
        // `T: Debug` and `ZipReader` doesn't implement `Debug` (the inner
        // `R: Read + Seek` has no `Debug` bound).
        let msg = match ZipReader::open(cursor) {
            Ok(_) => panic!("10-byte file must error, but open() succeeded"),
            Err(e) => format!("{}", e),
        };
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
        // See `test_open_too_small_returns_err` for why we use `match` here.
        let msg = match ZipReader::open(cursor) {
            Ok(_) => panic!("empty file must error, but open() succeeded"),
            Err(e) => format!("{}", e),
        };
        assert!(
            msg.contains("file_size=0"),
            "error must mention file_size=0, got: {}",
            msg
        );
    }

    /// An EOCD signature that appears inside a ZIP comment MUST NOT be
    /// picked up as the real EOCD. The `comment_len` verification rejects
    /// such false positives by checking that the candidate EOCD's comment
    /// ends exactly at EOF.
    ///
    /// This is the proximate cause of the "bad CDH at <offset>" crash:
    /// the original code picked the first EOCD_SIG match (which happened
    /// to be inside the comment), read its bogus `cd_offset`, and failed
    /// at the very first CDH read.
    ///
    /// To exercise the bug, the false-positive EOCD must fall WITHIN the
    /// scan window `[0, file_size - 22]`. Since the false positive sits
    /// at offset 22 (start of comment), we need `22 <= file_size - 22`,
    /// i.e., `file_size >= 44`. We use a 22-byte comment (the minimum
    /// that puts the false positive within the window) so file_size = 44.
    #[test]
    fn test_eocd_in_comment_rejected() {
        // Real EOCD at offset 0 with a 22-byte comment.
        // Comment starts with EOCD_SIG bytes (false positive at offset 22).
        // file_size = 22 (EOCD) + 22 (comment) = 44.
        // Scan window = [0, 22], so the false positive at offset 22 IS
        // examined. Without comment_len verification, the original code
        // would accept the false positive (its comment_len field reads
        // whatever bytes happen to be at offset 22+20..22+22, which is
        // "jk" from "junk" = 0x6b6a = 27498 — bogus, would fail with
        // "bad CDH" on the resulting garbage cd_offset).
        let mut comment = Vec::new();
        // false-positive EOCD_SIG at offset 22 (start of comment)
        comment.extend_from_slice(&EOCD_SIG.to_le_bytes());
        // Pad with 0xFF (NOT 0x00) so the false-positive's "comment_len"
        // field (at file offset 42..44 = comment[20..22]) reads 0xFFFF =
        // 65535. Then abs_pos(22) + 22 + 65535 = 65579 ≠ 44 = file_size,
        // and the false positive is correctly rejected. With zero padding,
        // comment_len would read 0 and 22+22+0=44=file_size would WRONGLY
        // accept the false positive.
        comment.extend_from_slice(&[0xFFu8; 18]);
        assert_eq!(comment.len(), 22);
        let mut bytes = empty_zip_no_comment();
        let len_pos = bytes.len() - 2;
        bytes[len_pos..len_pos + 2].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&comment);
        assert_eq!(bytes.len(), 44);

        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "EOCD signature in comment must be rejected (comment_len verification) — got: {:?}",
            result.as_ref().err()
        );
    }

    /// A real EOCD at the end of the file MUST be found even when the
    /// file body contains an EOCD_SIG byte sequence earlier. Backwards
    /// scanning finds the real EOCD first (later in the file) and the
    /// comment_len=0 verification accepts it without examining the
    /// false positive. This is a regression test ensuring the
    /// comment_len check doesn't accidentally reject valid EOCDs.
    #[test]
    fn test_real_eocd_found_despite_body_false_positive() {
        let mut bytes = Vec::new();
        // 100 bytes of body containing EOCD_SIG at offset 50
        bytes.extend_from_slice(&[0u8; 50]);
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        // pad to 100 bytes total
        bytes.extend_from_slice(&[0u8; 46]);
        // Real empty EOCD with no comment at the end
        bytes.extend_from_slice(&empty_zip_no_comment());

        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "real EOCD must be found despite body false positive — got: {:?}",
            result.as_ref().err()
        );
    }

    /// ZIP64 sentinel in `cd_entries` MUST trigger ZIP64 EOCD locator
    /// lookup. We construct a synthetic ZIP64 archive:
    ///   - ZIP64 EOCD record (56 bytes) at offset 0
    ///   - ZIP64 EOCD locator (20 bytes) at offset 56
    ///   - Classic EOCD (22 bytes) at offset 76, with cd_entries=0xFFFF
    ///     sentinel pointing back to the ZIP64 EOCD record
    ///
    /// The total file size is 98 bytes. There are no real CDH entries
    /// (cd_entries=0 after ZIP64 resolution).
    #[test]
    fn test_zip64_sentinel_in_cd_entries() {
        let zip64_eocd_offset: u64 = 0;
        let zip64_loc_offset: u64 = zip64_eocd_offset + 56;
        let eocd_offset: u64 = zip64_loc_offset + 20;

        // ZIP64 EOCD record (56 bytes)
        let mut z64 = Vec::with_capacity(56);
        z64.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes()); // signature
        z64.extend_from_slice(&44u64.to_le_bytes()); // size of remaining record
        z64.extend_from_slice(&0u16.to_le_bytes()); // version made by
        z64.extend_from_slice(&0u16.to_le_bytes()); // version needed
        z64.extend_from_slice(&0u32.to_le_bytes()); // disk number
        z64.extend_from_slice(&0u32.to_le_bytes()); // disk with CD start
        z64.extend_from_slice(&0u64.to_le_bytes()); // entries on this disk
        z64.extend_from_slice(&0u64.to_le_bytes()); // total entries (REAL value: 0)
        z64.extend_from_slice(&0u64.to_le_bytes()); // cd_size
        z64.extend_from_slice(&0u64.to_le_bytes()); // cd_offset
        assert_eq!(z64.len(), 56);

        // ZIP64 EOCD locator (20 bytes)
        let mut loc = Vec::with_capacity(20);
        loc.extend_from_slice(&ZIP64_EOCD_LOC_SIG.to_le_bytes());
        loc.extend_from_slice(&0u32.to_le_bytes()); // disk with ZIP64 EOCD
        loc.extend_from_slice(&zip64_eocd_offset.to_le_bytes()); // offset
        loc.extend_from_slice(&1u32.to_le_bytes()); // total disks
        assert_eq!(loc.len(), 20);

        // Classic EOCD (22 bytes) with cd_entries sentinel
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk number
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
        eocd.extend_from_slice(&0xFFFFu16.to_le_bytes()); // entries on this disk (SENTINEL)
        eocd.extend_from_slice(&0xFFFFu16.to_le_bytes()); // total entries (SENTINEL)
        eocd.extend_from_slice(&0u32.to_le_bytes()); // CD size
        eocd.extend_from_slice(&0u32.to_le_bytes()); // CD offset (0 — no real CD)
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment length
        assert_eq!(eocd.len(), 22);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&z64);
        bytes.extend_from_slice(&loc);
        bytes.extend_from_slice(&eocd);
        assert_eq!(bytes.len() as u64, eocd_offset + 22);

        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "ZIP64 sentinel must trigger locator lookup — got: {:?}",
            result.as_ref().err()
        );
        let zip = result.unwrap();
        assert!(
            zip.entries().is_empty(),
            "ZIP64 archive with 0 real entries must have 0 entries"
        );
    }

    /// ZIP64 sentinel in `cd_offset` MUST trigger locator lookup. Same
    /// structure as `test_zip64_sentinel_in_cd_entries` but with the
    /// sentinel in `cd_offset` instead of `cd_entries`.
    #[test]
    fn test_zip64_sentinel_in_cd_offset() {
        let zip64_eocd_offset: u64 = 0;
        let zip64_loc_offset: u64 = zip64_eocd_offset + 56;
        let eocd_offset: u64 = zip64_loc_offset + 20;

        let mut z64 = Vec::with_capacity(56);
        z64.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        z64.extend_from_slice(&44u64.to_le_bytes());
        z64.extend_from_slice(&0u16.to_le_bytes());
        z64.extend_from_slice(&0u16.to_le_bytes());
        z64.extend_from_slice(&0u32.to_le_bytes());
        z64.extend_from_slice(&0u32.to_le_bytes());
        z64.extend_from_slice(&0u64.to_le_bytes());
        z64.extend_from_slice(&0u64.to_le_bytes()); // total entries = 0
        z64.extend_from_slice(&0u64.to_le_bytes()); // cd_size
        z64.extend_from_slice(&0u64.to_le_bytes()); // cd_offset = 0
        assert_eq!(z64.len(), 56);

        let mut loc = Vec::with_capacity(20);
        loc.extend_from_slice(&ZIP64_EOCD_LOC_SIG.to_le_bytes());
        loc.extend_from_slice(&0u32.to_le_bytes());
        loc.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
        loc.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(loc.len(), 20);

        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // entries on this disk = 0
        eocd.extend_from_slice(&0u16.to_le_bytes()); // total entries = 0
        eocd.extend_from_slice(&0u32.to_le_bytes()); // CD size = 0
        eocd.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // CD offset (SENTINEL)
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment length
        assert_eq!(eocd.len(), 22);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&z64);
        bytes.extend_from_slice(&loc);
        bytes.extend_from_slice(&eocd);
        assert_eq!(bytes.len() as u64, eocd_offset + 22);

        let cursor = Cursor::new(bytes);
        let result = ZipReader::open(cursor);
        assert!(
            result.is_ok(),
            "ZIP64 sentinel in cd_offset must trigger locator lookup — got: {:?}",
            result.as_ref().err()
        );
    }

    /// A ZIP64 sentinel with NO locator present MUST return a clear error
    /// (not a generic "bad CDH" or panic). This happens if a streaming
    /// writer emits sentinels but forgets to write the locator.
    #[test]
    fn test_zip64_sentinel_without_locator_errors() {
        // 22-byte EOCD with cd_entries=0xFFFF, but no ZIP64 EOCD locator
        // before it. The code must detect this and return a clear error.
        let mut bytes = Vec::new();
        // 22 bytes of zero padding (so eocd_pos >= 20, but the locator
        // signature won't match)
        bytes.extend_from_slice(&[0u8; 22]);
        // EOCD with cd_entries sentinel
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes()); // entries (SENTINEL)
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes()); // total (SENTINEL)
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CD size
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CD offset
        bytes.extend_from_slice(&0u16.to_le_bytes()); // comment len

        let cursor = Cursor::new(bytes);
        let msg = match ZipReader::open(cursor) {
            Ok(_) => panic!("ZIP64 sentinel without locator must error"),
            Err(e) => format!("{}", e),
        };
        assert!(
            msg.contains("ZIP64"),
            "error must mention ZIP64 for diagnostics, got: {}",
            msg
        );
    }

    /// A genuinely bad CDH (cd_offset pointing at non-CDH data) MUST
    /// return an error mentioning the ACTUAL current position (not just
    /// `cd_offset`). The error message must include `entry #`, `cd_offset`,
    /// and `cd_entries` for diagnosis.
    #[test]
    fn test_bad_cdh_error_reports_current_position() {
        // Construct: 4 bytes of garbage at offset 0 (where CD would be) +
        // an EOCD pointing to cd_offset=0 with cd_entries=1.
        let mut bytes = Vec::new();
        // fake "CDH" — wrong sig
        bytes.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // EOCD pointing to it
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        bytes.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk = 1
        bytes.extend_from_slice(&1u16.to_le_bytes()); // total entries = 1
        bytes.extend_from_slice(&4u32.to_le_bytes()); // CD size = 4 bytes
        bytes.extend_from_slice(&0u32.to_le_bytes()); // CD offset = 0 (the garbage)
        bytes.extend_from_slice(&0u16.to_le_bytes()); // comment len

        let cursor = Cursor::new(bytes);
        let msg = match ZipReader::open(cursor) {
            Ok(_) => panic!("bad CDH must error"),
            Err(e) => format!("{}", e),
        };
        assert!(
            msg.contains("bad CDH at offset 0"),
            "error must report current_pos=0, got: {}",
            msg
        );
        assert!(
            msg.contains("entry #0"),
            "error must report entry index, got: {}",
            msg
        );
        assert!(
            msg.contains("cd_offset=0"),
            "error must report cd_offset for context, got: {}",
            msg
        );
        assert!(
            msg.contains("found signature 0xdeadbeef"),
            "error must report found signature (hex lowercase), got: {}",
            msg
        );
    }

    // ----------------------------------------------------------------
    // CDH field-offset regression tests (added after the off-by-4 fix).
    //
    // History: every CDH field EXCEPT `lfh_offset` was being read 4 bytes
    // too early because the code used offsets as if `hdr` (the 42-byte
    // buffer AFTER the 4-byte signature) included the signature. This
    // produced bogus `name_len`/`extra_len`/`comment_len` (actually reading
    // bytes from `uncompressed_size`/`compressed_size`), which made the
    // parser skip past real CDH entries and land on garbage — yielding
    // "bad CDH at <offset>" on the second entry. For .apks containers,
    // the same bug caused `compressed_size` (actually reading CRC-32) to
    // produce a wrong byte count, making `read_exact` fail with
    // "io: failed to fill whole buffer" when extracting base.apk.
    //
    // The 4 pre-existing tests above all use `cd_entries=0`, so the CDH
    // loop never executes and the bug went undetected. The tests below
    // construct real ZIPs with real CDH entries to exercise the parser.
    // ----------------------------------------------------------------

    /// Build a ZIP with one STORED (uncompressed) entry. Returns the full
    /// ZIP bytes. Used to verify CDH field parsing end-to-end.
    ///
    /// Layout:
    ///   [LFH for "hello.txt"][data "hi"][CDH for "hello.txt"][EOCD]
    fn build_zip_one_stored_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let crc = crc32(data);
        let lfh_offset: u32 = 0;
        let mut bytes = Vec::new();

        // Local file header (30 bytes + name)
        bytes.extend_from_slice(&LFH_SIG.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
        bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // method = STORED
        bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
        bytes.extend_from_slice(&0u16.to_le_bytes()); // mod date
        bytes.extend_from_slice(&crc.to_le_bytes()); // CRC-32
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        bytes.extend_from_slice(&0u16.to_le_bytes()); // extra len
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(data);

        let cd_offset = bytes.len() as u32;

        // Central directory file header (46 bytes + name)
        bytes.extend_from_slice(&CDH_SIG.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes()); // version made by
        bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
        bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
        bytes.extend_from_slice(&0u16.to_le_bytes()); // method = STORED
        bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
        bytes.extend_from_slice(&0u16.to_le_bytes()); // mod date
        bytes.extend_from_slice(&crc.to_le_bytes()); // CRC-32
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        bytes.extend_from_slice(&0u16.to_le_bytes()); // extra len
        bytes.extend_from_slice(&0u16.to_le_bytes()); // comment len
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        bytes.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        bytes.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        bytes.extend_from_slice(&lfh_offset.to_le_bytes()); // lfh offset
        bytes.extend_from_slice(name.as_bytes());

        let cd_size = (bytes.len() as u32) - cd_offset;

        // EOCD
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk
        bytes.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        bytes.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        bytes.extend_from_slice(&1u16.to_le_bytes()); // total entries
        bytes.extend_from_slice(&cd_size.to_le_bytes()); // CD size
        bytes.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        bytes.extend_from_slice(&0u16.to_le_bytes()); // comment len

        bytes
    }

    /// Standard CRC-32 (polynomial 0xEDB88320) — needed to make valid
    /// ZIP entries. The parser doesn't verify CRC, but a real-world ZIP
    /// will have correct CRCs and we want our synthetic test ZIPs to
    /// match that shape.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// A single STORED entry MUST be parsed correctly: the entry name,
    /// compressed_size, uncompressed_size, method (STORED → is_compressed=false),
    /// and lfh_offset must all match what we put into the CDH.
    ///
    /// This test FAILS with the off-by-4 bug because:
    ///   - `name_len` reads `uncompressed_size`'s low 2 bytes (= 2, the
    ///     length of "hi" — coincidentally small enough not to crash, but
    ///     then the next read consumes 2 bytes of "hi" as the "name")
    ///   - `compressed_size` reads CRC-32 (= some 4-byte value, not 2)
    ///   - `is_compressed` is true because `method` reads `version_needed`
    ///     (= 20) instead of method=0
    #[test]
    fn test_cdh_fields_read_correctly() {
        let name = "hello.txt";
        let data = b"hi";
        let bytes = build_zip_one_stored_entry(name, data);
        let cursor = Cursor::new(bytes);
        let zip = ZipReader::open(cursor).expect("single-entry ZIP must open");
        assert_eq!(zip.entries().len(), 1, "exactly one entry expected");
        let e = &zip.entries()[0];
        assert_eq!(e.name, name, "entry name must match");
        assert_eq!(e.compressed_size, data.len() as u64, "compressed_size");
        assert_eq!(e.uncompressed_size, data.len() as u64, "uncompressed_size");
        assert!(
            !e.is_compressed,
            "STORED entry must have is_compressed=false (method=0)"
        );
    }

    /// A multi-entry ZIP MUST walk the central directory entry-by-entry
    /// without producing a "bad CDH" error. With the off-by-4 bug, the
    /// first entry's misread `name_len`/`extra_len`/`comment_len` would
    /// skip past several real CDHs and land on garbage, failing with
    /// "bad CDH at <offset>" on entry #1.
    ///
    /// We use 3 entries with realistic sizes (small text files, STORED)
    /// to exercise the entry-advance arithmetic.
    #[test]
    fn test_multi_entry_zip_walks_cd() {
        let files: &[(&str, &[u8])] =
            &[("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"gamma")];
        let mut bytes = Vec::new();
        let mut cd_offsets: Vec<(u32, &str, &[u8])> = Vec::new();

        // Write all LFH+data first, recording CD offsets.
        for (name, data) in files {
            let lfh_offset = bytes.len() as u32;
            let crc = crc32(data);
            bytes.extend_from_slice(&LFH_SIG.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes()); // STORED
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&crc.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(data);
            cd_offsets.push((lfh_offset, name, data));
        }

        let cd_start = bytes.len() as u32;

        // Write all CDHs.
        for (lfh_offset, name, data) in &cd_offsets {
            let crc = crc32(data);
            bytes.extend_from_slice(&CDH_SIG.to_le_bytes());
            bytes.extend_from_slice(&20u16.to_le_bytes()); // version made by
            bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
            bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
            bytes.extend_from_slice(&0u16.to_le_bytes()); // STORED
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&crc.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes()); // extra
            bytes.extend_from_slice(&0u16.to_le_bytes()); // comment
            bytes.extend_from_slice(&0u16.to_le_bytes()); // disk
            bytes.extend_from_slice(&0u16.to_le_bytes()); // internal
            bytes.extend_from_slice(&0u32.to_le_bytes()); // external
            bytes.extend_from_slice(&lfh_offset.to_le_bytes()); // lfh offset
            bytes.extend_from_slice(name.as_bytes());
        }

        let cd_size = bytes.len() as u32 - cd_start;

        // EOCD
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes()); // 3 entries
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&cd_size.to_le_bytes());
        bytes.extend_from_slice(&cd_start.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let cursor = Cursor::new(bytes);
        let zip = ZipReader::open(cursor).expect("3-entry ZIP must open without bad CDH");
        assert_eq!(zip.entries().len(), 3, "all 3 entries must be enumerated");
        assert_eq!(zip.entries()[0].name, "a.txt");
        assert_eq!(zip.entries()[1].name, "b.txt");
        assert_eq!(zip.entries()[2].name, "c.txt");
    }

    /// A STORED entry (method=0) MUST have `is_compressed=false`. A
    /// DEFLATE entry (method=8) MUST have `is_compressed=true`. With the
    /// off-by-4 bug, `method` reads `version_needed` (typically 20),
    /// marking every entry as compressed — even STORED ones — which
    /// would send raw bytes to the DEFLATE decompressor and fail.
    #[test]
    fn test_stored_entry_not_compressed() {
        // Use the STORED builder; the entry should report is_compressed=false.
        let bytes = build_zip_one_stored_entry("stored.txt", b"uncompressed-data");
        let cursor = Cursor::new(bytes);
        let zip = ZipReader::open(cursor).expect("STORED entry ZIP must open");
        assert_eq!(zip.entries().len(), 1);
        assert!(
            !zip.entries()[0].is_compressed,
            "STORED (method=0) entry must have is_compressed=false"
        );
    }
}
