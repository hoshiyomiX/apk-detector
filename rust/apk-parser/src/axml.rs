//! Minimal Android binary XML (AXML) decoder.
//!
//! Android packages `AndroidManifest.xml` and resources as a custom binary
//! format ("AXML"). We decode just enough to extract the high-value fields
//! used by static detection:
//!
//!  - `package` attribute on `<manifest>`
//!  - `<uses-permission android:name="..." />`
//!  - `<application>` attributes: `android:name`, `android:debuggable`,
//!    `android:allowBackup`, `android:networkSecurityConfig`
//!  - `<meta-data android:name="..." android:value="..." />` (used by SDK init)
//!  - `<uses-sdk android:minSdkVersion android:targetSdkVersion />`
//!
//! Format reference: AOSP `frameworks/base/include/androidfw/ResourceTypes.h`
//! `ResXMLTree` / `ResChunk_header`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AxmlError {
    #[error("not AXML: bad magic 0x{0:08x}")]
    BadMagic(u16),
    #[error("truncated chunk at offset {0}")]
    Truncated(usize),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;

// Attribute field indices (AOSP ATTR_IX_*). Each field is a 4-byte unit
// in the attribute array.
#[allow(dead_code)] // documents AOSP layout; consumed by future attribute readers
const ATTR_IX_NS: usize = 0;
const ATTR_IX_NAME: usize = 1;
#[allow(dead_code)] // documents AOSP layout; consumed by future attribute readers
const ATTR_IX_VALUE: usize = 2; // rawValue (string pool index when type=string)
const ATTR_IX_TYPE: usize = 3; // Res_value (size:u16, res0:u8, dataType:u8, data:u32)
const ATTR_IX_DATA: usize = 4; // data field of Res_value (after the u32 of ATTR_IX_TYPE)

const STRING_POOL_FLAG_UTF8: u32 = 1 << 8;

#[derive(Debug, Clone)]
pub struct BinaryXml {
    /// String pool — index into this resolves string references in chunks.
    pub strings: Vec<String>,
    /// Decoded XML elements in document order.
    pub elements: Vec<XmlElement>,
}

#[derive(Debug, Clone)]
pub struct XmlElement {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
}

impl BinaryXml {
    pub fn parse_slice(bytes: &[u8]) -> Result<Self, AxmlError> {
        let mut p = Parser { b: bytes, pos: 0 };
        p.parse_document()
    }

    /// Quick accessor: the `package` attribute on the root `<manifest>`.
    pub fn package(&self) -> Option<&str> {
        self.elements.first().and_then(|e| {
            e.attrs
                .iter()
                .find(|(k, _)| k == "package")
                .map(|(_, v)| v.as_str())
        })
    }

    /// All `<uses-permission android:name="..." />` values.
    pub fn permissions(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for e in &self.elements {
            if e.tag == "uses-permission" {
                if let Some((_, v)) = e.attrs.iter().find(|(k, _)| k == "name") {
                    out.push(v.as_str());
                }
            }
        }
        out
    }

    /// `<application android:name="..."/>` (the Application subclass).
    pub fn application_name(&self) -> Option<&str> {
        self.elements
            .iter()
            .find(|e| e.tag == "application")
            .and_then(|e| e.attrs.iter().find(|(k, _)| k == "name"))
            .map(|(_, v)| v.as_str())
    }

    /// All `<meta-data android:name="..."/>` values (used by SDK init).
    pub fn meta_data_names(&self) -> Vec<&str> {
        self.elements
            .iter()
            .filter(|e| e.tag == "meta-data")
            .filter_map(|e| e.attrs.iter().find(|(k, _)| k == "name"))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn parse_document(&mut self) -> Result<BinaryXml, AxmlError> {
        let typ = self.peek_u16(self.pos + 2)?;
        if typ != RES_XML_TYPE {
            return Err(AxmlError::BadMagic(typ));
        }
        // Skip the 8-byte document header
        let doc_size = self.peek_u32(self.pos + 4)? as usize;
        let doc_end = self.pos + doc_size;
        self.pos += 8;

        let mut strings: Vec<String> = Vec::new();
        let mut elements: Vec<XmlElement> = Vec::new();

        while self.pos < doc_end {
            let chunk_start = self.pos;
            let chunk_type = self.peek_u16(chunk_start + 2)?;
            let _chunk_header_size = self.peek_u16(chunk_start + 4)? as usize;
            let chunk_size = self.peek_u32(chunk_start + 4)? as usize;
            let next = chunk_start + chunk_size;
            if next > doc_end {
                return Err(AxmlError::Truncated(next));
            }

            match chunk_type {
                RES_STRING_POOL_TYPE => {
                    strings = self.parse_string_pool(chunk_start)?;
                }
                RES_XML_RESOURCE_MAP_TYPE => {
                    // Skip — string indices are sufficient for our needs.
                }
                RES_XML_START_ELEMENT_TYPE => {
                    let el = self.parse_start_element(chunk_start, &strings)?;
                    elements.push(el);
                }
                RES_XML_END_ELEMENT_TYPE | RES_XML_CDATA_TYPE => {
                    // No-op; we don't track tag nesting for static analysis.
                }
                _ => { /* unknown chunk — skip */ }
            }
            self.pos = next;
        }

        Ok(BinaryXml { strings, elements })
    }

    fn parse_string_pool(&self, start: usize) -> Result<Vec<String>, AxmlError> {
        let string_count = self.peek_u32(start + 8)? as usize;
        let _style_count = self.peek_u32(start + 12)? as usize;
        let flags = self.peek_u32(start + 16)?;
        let strings_start = self.peek_u32(start + 20)? as usize + start;

        let is_utf8 = (flags & STRING_POOL_FLAG_UTF8) != 0;

        let mut offsets = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off = self.peek_u32(start + 28 + i * 4)? as usize;
            offsets.push(off);
        }

        let mut out = Vec::with_capacity(string_count);
        for off in offsets {
            let p = strings_start + off;
            let s = if is_utf8 {
                self.read_utf8(p)?
            } else {
                self.read_utf16(p)?
            };
            out.push(s);
        }
        Ok(out)
    }

    fn read_utf8(&self, p: usize) -> Result<String, AxmlError> {
        // AOSP UTF-8 string: [charsLen][charsLen?][bytesLen][bytesLen?][bytes][0x00]
        let (chars_len, n) = decode_len(self.b, p)?;
        let (_bytes_len, m) = decode_len(self.b, p + n)?;
        let str_start = p + n + m;
        let str_end = str_start + chars_len;
        if str_end > self.b.len() {
            return Err(AxmlError::Truncated(str_end));
        }
        Ok(String::from_utf8_lossy(&self.b[str_start..str_end]).into_owned())
    }

    fn read_utf16(&self, p: usize) -> Result<String, AxmlError> {
        let len = self.peek_u16(p)? as usize;
        let bytes_start = p + 2;
        let bytes_end = bytes_start + len * 2;
        if bytes_end > self.b.len() {
            return Err(AxmlError::Truncated(bytes_end));
        }
        let mut out = String::with_capacity(len);
        for i in 0..len {
            let lo = self.b[bytes_start + i * 2];
            let hi = self.b[bytes_start + i * 2 + 1];
            let code = u16::from_le_bytes([lo, hi]);
            if let Some(c) = char::from_u32(code as u32) {
                out.push(c);
            } else {
                out.push('\u{FFFD}');
            }
        }
        Ok(out)
    }

    fn parse_start_element(
        &self,
        start: usize,
        strings: &[String],
    ) -> Result<XmlElement, AxmlError> {
        // ResXMLTree_attrExt layout (offsets from chunk start):
        //   +0   ResChunk_header (type+headersize+size)
        //   +8   lineNumber (u32)
        //   +12  comment (u32) -> string pool index
        //   +16  ns (u32) -> string pool index
        //   +20  name (u32) -> string pool index
        //   +24  attributeStart (u16) — typically 0x14 = 20 (info only)
        //   +26  attributeSize (u16)  — typically 0x14 = 20 bytes
        //   +28  attributeCount (u16)
        //   +30  idIndex, classIndex, styleIndex (3 * u16)
        //   +36  attributes[attributeCount] — each attributeSize bytes
        let name_idx = self.peek_u32(start + 20)? as i32;
        let attr_size = self.peek_u16(start + 26)? as usize;
        let attr_count = self.peek_u16(start + 28)? as usize;

        let tag = if name_idx >= 0 && (name_idx as usize) < strings.len() {
            strings[name_idx as usize].clone()
        } else {
            String::new()
        };

        let attr_size = if attr_size == 0 { 20 } else { attr_size };

        let mut attrs = Vec::with_capacity(attr_count);
        let attr_base = start + 36;
        for i in 0..attr_count {
            let p = attr_base + i * attr_size;
            // Each attribute is 20 bytes:
            //   +0  ns (u32)
            //   +4  name (u32, string pool index)
            //   +8  rawValue (u32, string pool index when type=string)
            //   +12 Res_value: size(u16), res0(u8), dataType(u8), data(u32)
            //   +16 data (u32)
            let attr_name_idx = self.peek_u32(p + ATTR_IX_NAME * 4)? as i32;
            // The Res_value word at ATTR_IX_TYPE*4 = offset 12 contains
            // size in low 16 bits, res0 in bits 16-23, dataType in bits 24-31.
            let attr_type_word = self.peek_u32(p + ATTR_IX_TYPE * 4)?;
            let attr_type = ((attr_type_word >> 24) & 0xff) as u8;
            let attr_data = self.peek_u32(p + ATTR_IX_DATA * 4)?;

            let name = if attr_name_idx >= 0 && (attr_name_idx as usize) < strings.len() {
                strings[attr_name_idx as usize].clone()
            } else {
                continue;
            };

            // TYPE_STRING = 0x03 -> data is string pool index
            // TYPE_INT_DEC = 0x10, TYPE_INT_HEX = 0x11, TYPE_INT_BOOLEAN = 0x12
            let value = if attr_type == 0x03 {
                let s_idx = attr_data as i32;
                if s_idx >= 0 && (s_idx as usize) < strings.len() {
                    strings[s_idx as usize].clone()
                } else {
                    String::new()
                }
            } else if attr_type == 0x12 {
                if attr_data != 0 {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            } else {
                attr_data.to_string()
            };
            attrs.push((name, value));
        }

        Ok(XmlElement { tag, attrs })
    }

    fn peek_u16(&self, p: usize) -> Result<u16, AxmlError> {
        if p + 2 > self.b.len() {
            return Err(AxmlError::Truncated(p + 2));
        }
        Ok(u16::from_le_bytes([self.b[p], self.b[p + 1]]))
    }
    fn peek_u32(&self, p: usize) -> Result<u32, AxmlError> {
        if p + 4 > self.b.len() {
            return Err(AxmlError::Truncated(p + 4));
        }
        Ok(u32::from_le_bytes([
            self.b[p],
            self.b[p + 1],
            self.b[p + 2],
            self.b[p + 3],
        ]))
    }
}

fn decode_len(b: &[u8], p: usize) -> Result<(usize, usize), AxmlError> {
    if p >= b.len() {
        return Err(AxmlError::Truncated(p));
    }
    let first = b[p];
    if first & 0x80 != 0 {
        if p + 1 >= b.len() {
            return Err(AxmlError::Truncated(p + 1));
        }
        let len = ((first & 0x7f) as usize) << 8 | b[p + 1] as usize;
        Ok((len, 2))
    } else {
        Ok((first as usize, 1))
    }
}
