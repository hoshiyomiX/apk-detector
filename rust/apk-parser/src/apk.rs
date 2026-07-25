//! Top-level APK handle. Opens a ZIP, exposes typed accessors.

use std::io::{Cursor, Read, Seek};
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

/// Combined `Read + Seek` trait so we can use `Box<dyn ReadSeek>`. Rust
/// forbids `dyn Read + Seek` directly (E0225: only auto traits can be
/// used as additional traits in a trait object) because neither `Read`
/// nor `Seek` is an auto trait. The standard workaround is a marker
/// trait with both as supertraits plus a blanket impl.
pub trait ReadSeek: Read + Seek {}

// Blanket impl: any type that implements `Read + Seek` automatically
// implements `ReadSeek`. This lets `Box<File>`, `Box<Cursor<Vec<u8>>>`,
// etc. coerce to `Box<dyn ReadSeek>` via unsized coercion.
impl<R: Read + Seek> ReadSeek for R {}

/// Type-erased `Read + Seek` so we can return a single `Apk` type from
/// `open_any` regardless of whether the source is a `File` (regular APK)
/// or a `Cursor<Vec<u8>>` (base.apk extracted from an `.apks` container).
pub type AnyReader = Box<dyn ReadSeek>;

/// Open an APK or `.apks` container transparently.
///
/// `.apks` is the BundleTool output format: a ZIP whose entries are
/// `base.apk`, `splits/*.apk`, and `toc.pb`. To scan an `.apks` we:
///   1. Open the outer ZIP with our existing `ZipReader`.
///   2. Find the `base.apk` entry (preferred name "base.apk"; fallback to
///      any top-level `*.apk` entry — splits live under `splits/`).
///   3. Read its decompressed bytes into memory.
///   4. Open the inner APK with `ZipReader` again (recursively).
///
/// Detection is by file extension. Content-based detection (peek at first
/// entry name) is deferred — extension is sufficient for the BundleTool
/// output the user picks via the SAF picker.
///
/// For regular `.apk` files, this delegates to `Apk::open(reader)` without
/// reading the whole file into memory.
pub fn open_any(reader: AnyReader, file_path: &str) -> Result<Apk<AnyReader>, ApkError> {
    let lower = file_path.to_ascii_lowercase();
    if lower.ends_with(".apks") {
        let mut zip = ZipReader::open(reader)?;
        // Find base.apk. Prefer the exact name "base.apk"; fall back to any
        // top-level entry ending in ".apk" (i.e., not under "splits/").
        let base_name = zip
            .entries()
            .iter()
            .find(|e| e.name == "base.apk")
            .map(|e| e.name.clone())
            .or_else(|| {
                zip.entries()
                    .iter()
                    .find(|e| e.name.ends_with(".apk") && !e.name.contains('/'))
                    .map(|e| e.name.clone())
            })
            .ok_or_else(|| {
                ApkError::Zip(
                    "apks container has no .apk entry (expected base.apk or top-level *.apk)"
                        .to_string(),
                )
            })?;
        let bytes = zip.read(&base_name)?;
        let inner: AnyReader = Box::new(Cursor::new(bytes));
        Apk::open(inner)
    } else {
        Apk::open(reader)
    }
}
