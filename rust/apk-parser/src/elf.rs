//! ELF architecture sniffing.
//!
//! Reads just the first 20 bytes of an ELF file to determine its architecture.
//! Used to enumerate `lib/<abi>/*.so` entries in the APK and detect cross-arch
//! fingerprinting tricks.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfArch {
    Arm32,  // armeabi-v7a
    Arm64,  // arm64-v8a
    X86,    // x86
    X86_64, // x86_64
    Mips,
    Mips64,
    Unknown,
}

/// Inspect the first 20 bytes of an ELF file and return its architecture.
pub fn sniff_arch(bytes: &[u8]) -> Result<ElfArch, &'static str> {
    if bytes.len() < 20 {
        return Err("truncated ELF header");
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF file");
    }
    // bytes[4] = EI_CLASS: 1=32bit, 2=64bit
    // bytes[5] = EI_DATA:  1=LE, 2=BE
    // bytes[18..20] = e_machine (LE u16)
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    Ok(match machine {
        0x28 => ElfArch::Arm32,
        0xB7 => ElfArch::Arm64,
        0x03 => ElfArch::X86,
        0x3E => ElfArch::X86_64,
        0x08 => ElfArch::Mips,
        0x33 => ElfArch::Mips64,
        _ => ElfArch::Unknown,
    })
}

impl ElfArch {
    pub fn abi_name(&self) -> &'static str {
        match self {
            ElfArch::Arm32 => "armeabi-v7a",
            ElfArch::Arm64 => "arm64-v8a",
            ElfArch::X86 => "x86",
            ElfArch::X86_64 => "x86_64",
            ElfArch::Mips => "mips",
            ElfArch::Mips64 => "mips64",
            ElfArch::Unknown => "unknown",
        }
    }
}
