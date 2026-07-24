//! Top-level APK handle. Opens a ZIP, exposes typed accessors.

use std::io::{Read, Seek};
use thiserror::Error;

use crate::elf::ElfArch;
use crate::zip_reader::ZipReader;

#[derive(Debug, Error)]
pub enum ApkError {
    #[error("zip read error: {0}")]
    Zip(String),
    #[error("entry not found: {0}")]
    NotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One entry in the ZIP central directory of an APK.
#[derive(Debug, Clone)]
pub struct ApkEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_compressed: bool,
}

/// A native library under `lib/<abi>/`.
#[derive(Debug, Clone)]
pub struct NativeLib {
    pub abi: String,
    pub filename: String,
    pub uncompressed_size: u64,
    pub arch: Option<ElfArch>,
}

/// Open APK handle. Generic over Read+Seek so it works with `File` and `Cursor`.
pub struct Apk<R: Read + Seek> {
    zip: ZipReader<R>,
}

impl<R: Read + Seek> Apk<R> {
    pub fn open(reader: R) -> Result<Self, ApkError> {
        Ok(Self {
            zip: ZipReader::open(reader)?,
        })
    }

    /// List every entry in the APK.
    pub fn entries(&self) -> &[ApkEntry] {
        self.zip.entries()
    }

    /// Read a single entry's decompressed bytes.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>, ApkError> {
        self.zip.read(name)
    }

    /// Convenience: read `AndroidManifest.xml`.
    pub fn manifest(&mut self) -> Result<Vec<u8>, ApkError> {
        self.read("AndroidManifest.xml")
    }

    /// Convenience: list all `classes*.dex` entries (multidex-aware).
    pub fn dex_entries(&self) -> Vec<&ApkEntry> {
        self.zip
            .entries()
            .iter()
            .filter(|e| {
                e.name == "classes.dex" || e.name.starts_with("classes") && e.name.ends_with(".dex")
            })
            .collect()
    }

    /// Convenience: list all entries under `lib/<abi>/*.so` with arch sniff.
    pub fn native_libs(&mut self) -> Result<Vec<NativeLib>, ApkError> {
        // Collect candidate entries first to release the immutable borrow before
        // we call `self.zip.read(...)` (which takes &mut self).
        let candidates: Vec<(String, String, u64)> = self
            .zip
            .entries()
            .iter()
            .filter_map(|e| {
                if !e.name.starts_with("lib/") || !e.name.ends_with(".so") {
                    return None;
                }
                // lib/<abi>/<file>.so
                let parts: Vec<&str> = e.name.split('/').collect();
                if parts.len() != 3 {
                    return None;
                }
                Some((
                    parts[1].to_string(),
                    parts[2].to_string(),
                    e.uncompressed_size,
                ))
            })
            .collect();

        let mut out = Vec::with_capacity(candidates.len());
        for (abi, filename, uncompressed_size) in candidates {
            let path = format!("lib/{}/{}", abi, filename);
            let arch = if uncompressed_size > 20 {
                // Sniff first 20 bytes for ELF magic + e_machine.
                match self.zip.read(&path) {
                    Ok(bytes) => crate::elf::sniff_arch(&bytes).ok(),
                    Err(_) => None,
                }
            } else {
                None
            };
            out.push(NativeLib {
                abi,
                filename,
                uncompressed_size,
                arch,
            });
        }
        Ok(out)
    }
}
