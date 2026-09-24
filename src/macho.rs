use crate::demangle::demangle;
use crate::disasm::{Architecture, disasm_and_format_code};
use crate::dump::{Dump, DumpRawData};
use crate::reader::Reader;

use strum::IntoEnumIterator;
use strum_macros::{EnumIter, FromRepr, IntoStaticStr};

use std::collections::HashMap;
use std::path::PathBuf;

/*
 * https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 * https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h
 */

pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_CIGAM: u32 = 0xcefaedfe;
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_MAGIC_64: u32 = 0xcafebabf;

/// Java class files share FAT_MAGIC, their minor/major version makes this value much bigger
const FAT_MAX_ARCHS: u32 = 20;

pub fn is_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }

    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let nfat_arch = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    return match magic {
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => true,
        FAT_MAGIC | FAT_MAGIC_64 => nfat_arch > 0 && nfat_arch < FAT_MAX_ARCHS,
        _ => false,
    };
}

fn read_c_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }

    let bytes = &data[offset..];
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    return String::from_utf8_lossy(&bytes[..nul]).to_string();
}

fn format_version(version: u32) -> String {
    return format!("{}.{}.{}", version >> 16, (version >> 8) & 0xff, version & 0xff);
}

/*
 * CPU Type (cputype in mach header and fat arch)
 */

const CPU_ARCH_ABI64: u32 = 0x01000000;
const CPU_ARCH_ABI64_32: u32 = 0x02000000;
const CPU_SUBTYPE_MASK: u32 = 0xff000000;
const CPU_SUBTYPE_ARM64E: u32 = 2;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum CpuType {
    X86 = 7,
    X86_64 = 7 | CPU_ARCH_ABI64,
    Arm = 12,
    Arm64 = 12 | CPU_ARCH_ABI64,
    Arm64_32 = 12 | CPU_ARCH_ABI64_32,
    PowerPC = 18,
    PowerPC64 = 18 | CPU_ARCH_ABI64,
}

pub fn cpu_name(cputype: u32, cpusubtype: u32) -> String {
    match CpuType::from_repr(cputype) {
        Some(CpuType::X86) => "i386".to_string(),
        Some(CpuType::X86_64) => "x86_64".to_string(),
        Some(CpuType::Arm) => "arm".to_string(),
        Some(CpuType::Arm64) if (cpusubtype & !CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E => "arm64e".to_string(),
        Some(CpuType::Arm64) => "arm64".to_string(),
        Some(CpuType::Arm64_32) => "arm64_32".to_string(),
        Some(CpuType::PowerPC) => "ppc".to_string(),
        Some(CpuType::PowerPC64) => "ppc64".to_string(),
        None => format!("Unknown ({:#x})", cputype),
    }
}

/*
 * File Type (filetype in mach header)
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FileType {
    MhObject = 0x1,
    MhExecute = 0x2,
    MhFvmlib = 0x3,
    MhCore = 0x4,
    MhPreload = 0x5,
    MhDylib = 0x6,
    MhDylinker = 0x7,
    MhBundle = 0x8,
    MhDylibStub = 0x9,
    MhDsym = 0xa,
    MhKextBundle = 0xb,
    MhFileset = 0xc,
}

/*
 * Header Flags (flags in mach header)
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum HeaderFlag {
    MhNoundefs = 0x1,
    MhIncrlink = 0x2,
    MhDyldlink = 0x4,
    MhBindatload = 0x8,
    MhPrebound = 0x10,
    MhSplitSegs = 0x20,
    MhLazyInit = 0x40,
    MhTwolevel = 0x80,
    MhForceFlat = 0x100,
    MhNomultidefs = 0x200,
    MhNofixprebinding = 0x400,
    MhPrebindable = 0x800,
    MhAllmodsbound = 0x1000,
    MhSubsectionsViaSymbols = 0x2000,
    MhCanonical = 0x4000,
    MhWeakDefines = 0x8000,
    MhBindsToWeak = 0x10000,
    MhAllowStackExecution = 0x20000,
    MhRootSafe = 0x40000,
    MhSetuidSafe = 0x80000,
    MhNoReexportedDylibs = 0x100000,
    MhPie = 0x200000,
    MhDeadStrippableDylib = 0x400000,
    MhHasTlvDescriptors = 0x800000,
    MhNoHeapExecution = 0x1000000,
    MhAppExtensionSafe = 0x2000000,
    MhNlistOutofsyncWithDyldinfo = 0x4000000,
    MhSimSupport = 0x8000000,
    MhDylibInCache = 0x80000000,
}

impl HeaderFlag {
    pub fn flags_as_string(flags: u32) -> String {
        let str_flags: Vec<&'static str> = HeaderFlag::iter()
            .filter(|&flag| (flag as u32 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return str_flags.join(" | ");
    }
}

/*
 * Mach Header
 */

#[derive(Clone, Debug, Default)]
pub struct MachOHeader {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    /// Only present in 64-bit headers
    pub reserved: u32,
}

impl MachOHeader {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.magic = reader.read_u32()?;
        header.cputype = reader.read_u32()?;
        header.cpusubtype = reader.read_u32()?;
        header.filetype = reader.read_u32()?;
        header.ncmds = reader.read_u32()?;
        header.sizeofcmds = reader.read_u32()?;
        header.flags = reader.read_u32()?;

        if header.is_64() {
            header.reserved = reader.read_u32()?;
        }

        return Ok(header);
    }

    pub fn is_64(&self) -> bool {
        return self.magic == MH_MAGIC_64;
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Mach-O Header ({})", if self.is_64() { "64-bit" } else { "32-bit" }));

        dump.push_field("magic", format!("{:#x}", self.magic), Some("Mach magic number identifier"));
        dump.push_field("cputype", format!("{:#x} ({})", self.cputype, cpu_name(self.cputype, self.cpusubtype)), Some("CPU specifier"));
        dump.push_field("cpusubtype", format!("{:#x}", self.cpusubtype), Some("Machine specifier"));
        dump.push_field("filetype", format!("{:#x} ({})", self.filetype, FileType::from_repr(self.filetype).map_or("Unknown", |t| t.into())), Some("Type of file"));
        dump.push_field("ncmds", format!("{}", self.ncmds), Some("Number of load commands"));
        dump.push_field("sizeofcmds", format!("{:#x}", self.sizeofcmds), Some("The size of all the load commands"));
        dump.push_field("flags", format!("{:#x} ({})", self.flags, HeaderFlag::flags_as_string(self.flags)), Some("Flags"));

        if self.is_64() {
            dump.push_field("reserved", format!("{:#x}", self.reserved), Some("Reserved"));
        }

        return dump;
    }
}

/*
 * Fat (Universal) Header, always big endian
 */

#[derive(Clone, Debug, Default)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

impl FatArch {
    pub fn from_reader(reader: &mut Reader, is_64: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut arch = Self::default();

        arch.cputype = reader.read_u32()?;
        arch.cpusubtype = reader.read_u32()?;

        if is_64 {
            arch.offset = reader.read_u64()?;
            arch.size = reader.read_u64()?;
            arch.align = reader.read_u32()?;
            reader.read_u32()?;
        } else {
            arch.offset = reader.read_u32()? as u64;
            arch.size = reader.read_u32()? as u64;
            arch.align = reader.read_u32()?;
        }

        return Ok(arch);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Fat Arch ({})", cpu_name(self.cputype, self.cpusubtype)));

        dump.push_field("cputype", format!("{:#x}", self.cputype), Some("CPU specifier"));
        dump.push_field("cpusubtype", format!("{:#x}", self.cpusubtype), Some("Machine specifier"));
        dump.push_field("offset", format!("{:#x}", self.offset), Some("File offset to this object file"));
        dump.push_field("size", format!("{:#x}", self.size), Some("Size of this object file"));
        dump.push_field("align", format!("{:#x} (2^{})", 1u64 << self.align.min(63), self.align), Some("Alignment as a power of 2"));

        return dump;
    }
}

#[derive(Clone, Debug, Default)]
pub struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
    pub archs: Vec<FatArch>,
}

impl FatHeader {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.magic = reader.read_u32()?;
        header.nfat_arch = reader.read_u32()?;

        for _ in 0..header.nfat_arch {
            header.archs.push(FatArch::from_reader(reader, header.magic == FAT_MAGIC_64)?);
        }

        return Ok(header);
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Fat Header");

        dump.push_field("magic", format!("{:#x}", self.magic), Some("FAT_MAGIC or FAT_MAGIC_64"));
        dump.push_field("nfat_arch", format!("{}", self.nfat_arch), Some("Number of structs that follow"));

        for arch in self.archs.iter() {
            dump.push_child(arch.dump());
        }

        return dump;
    }
}

/*
 * Load Commands
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum LoadCommandType {
    LcSegment = 0x1,
    LcSymtab = 0x2,
    LcSymseg = 0x3,
    LcThread = 0x4,
    LcUnixthread = 0x5,
    LcDysymtab = 0xb,
    LcLoadDylib = 0xc,
    LcIdDylib = 0xd,
    LcLoadDylinker = 0xe,
    LcIdDylinker = 0xf,
    LcPreboundDylib = 0x10,
    LcRoutines = 0x11,
    LcSubFramework = 0x12,
    LcSubUmbrella = 0x13,
    LcSubClient = 0x14,
    LcSubLibrary = 0x15,
    LcTwolevelHints = 0x16,
    LcPrebindCksum = 0x17,
    LcLoadWeakDylib = 0x80000018,
    #[strum(serialize = "LC_SEGMENT_64")]
    LcSegment64 = 0x19,
    #[strum(serialize = "LC_ROUTINES_64")]
    LcRoutines64 = 0x1a,
    LcUuid = 0x1b,
    LcRpath = 0x8000001c,
    LcCodeSignature = 0x1d,
    LcSegmentSplitInfo = 0x1e,
    LcReexportDylib = 0x8000001f,
    LcLazyLoadDylib = 0x20,
    LcEncryptionInfo = 0x21,
    LcDyldInfo = 0x22,
    LcDyldInfoOnly = 0x80000022,
    LcLoadUpwardDylib = 0x80000023,
    LcVersionMinMacosx = 0x24,
    LcVersionMinIphoneos = 0x25,
    LcFunctionStarts = 0x26,
    LcDyldEnvironment = 0x27,
    LcMain = 0x80000028,
    LcDataInCode = 0x29,
    LcSourceVersion = 0x2a,
    LcDylibCodeSignDrs = 0x2b,
    #[strum(serialize = "LC_ENCRYPTION_INFO_64")]
    LcEncryptionInfo64 = 0x2c,
    LcLinkerOption = 0x2d,
    LcLinkerOptimizationHint = 0x2e,
    LcVersionMinTvos = 0x2f,
    LcVersionMinWatchos = 0x30,
    LcNote = 0x31,
    LcBuildVersion = 0x32,
    LcDyldExportsTrie = 0x80000033,
    LcDyldChainedFixups = 0x80000034,
    LcFilesetEntry = 0x80000035,
    LcAtomInfo = 0x36,
}

/*
 * Sections
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionType {
    SRegular = 0x0,
    SZerofill = 0x1,
    SCstringLiterals = 0x2,
    #[strum(serialize = "S_4BYTE_LITERALS")]
    S4ByteLiterals = 0x3,
    #[strum(serialize = "S_8BYTE_LITERALS")]
    S8ByteLiterals = 0x4,
    SLiteralPointers = 0x5,
    SNonLazySymbolPointers = 0x6,
    SLazySymbolPointers = 0x7,
    SSymbolStubs = 0x8,
    SModInitFuncPointers = 0x9,
    SModTermFuncPointers = 0xa,
    SCoalesced = 0xb,
    SGbZerofill = 0xc,
    SInterposing = 0xd,
    #[strum(serialize = "S_16BYTE_LITERALS")]
    S16ByteLiterals = 0xe,
    SDtraceDof = 0xf,
    SLazyDylibSymbolPointers = 0x10,
    SThreadLocalRegular = 0x11,
    SThreadLocalZerofill = 0x12,
    SThreadLocalVariables = 0x13,
    SThreadLocalVariablePointers = 0x14,
    SThreadLocalInitFunctionPointers = 0x15,
    SInitFuncOffsets = 0x16,
}

const SECTION_TYPE_MASK: u32 = 0xff;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionAttribute {
    SAttrPureInstructions = 0x80000000,
    SAttrNoToc = 0x40000000,
    SAttrStripStaticSyms = 0x20000000,
    SAttrNoDeadStrip = 0x10000000,
    SAttrLiveSupport = 0x08000000,
    SAttrSelfModifyingCode = 0x04000000,
    SAttrDebug = 0x02000000,
    SAttrSomeInstructions = 0x400,
    SAttrExtReloc = 0x200,
    SAttrLocReloc = 0x100,
}

impl SectionAttribute {
    pub fn flags_as_string(flags: u32) -> String {
        let str_flags: Vec<&'static str> = SectionAttribute::iter()
            .filter(|&flag| (flag as u32 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return str_flags.join(" | ");
    }
}

#[derive(Clone, Debug, Default)]
pub struct MachOSectionHeader {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    /// Only present in 64-bit sections
    pub reserved3: u32,
}

impl MachOSectionHeader {
    pub fn from_reader(reader: &mut Reader, is_64: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.sectname = read_c_string(&reader.read_n::<16>()?, 0);
        header.segname = read_c_string(&reader.read_n::<16>()?, 0);

        if is_64 {
            header.addr = reader.read_u64()?;
            header.size = reader.read_u64()?;
        } else {
            header.addr = reader.read_u32()? as u64;
            header.size = reader.read_u32()? as u64;
        }

        header.offset = reader.read_u32()?;
        header.align = reader.read_u32()?;
        header.reloff = reader.read_u32()?;
        header.nreloc = reader.read_u32()?;
        header.flags = reader.read_u32()?;
        header.reserved1 = reader.read_u32()?;
        header.reserved2 = reader.read_u32()?;

        if is_64 {
            header.reserved3 = reader.read_u32()?;
        }

        return Ok(header);
    }

    pub fn full_name(&self) -> String {
        return format!("{},{}", self.segname, self.sectname);
    }

    pub fn section_type(&self) -> Option<SectionType> {
        return SectionType::from_repr(self.flags & SECTION_TYPE_MASK);
    }

    pub fn is_zerofill(&self) -> bool {
        return matches!(self.section_type(), Some(SectionType::SZerofill | SectionType::SGbZerofill | SectionType::SThreadLocalZerofill));
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Section Header");

        let section_type: &'static str = self.section_type().map_or("Unknown", |t| t.into());
        let attributes = SectionAttribute::flags_as_string(self.flags);
        let flags = if attributes.is_empty() { section_type.to_string() } else { format!("{} | {}", section_type, attributes) };

        dump.push_field("sectname", self.sectname.clone(), Some("Name of this section"));
        dump.push_field("segname", self.segname.clone(), Some("Segment this section goes in"));
        dump.push_field("addr", format!("{:#x}", self.addr), Some("Memory address of this section"));
        dump.push_field("size", format!("{:#x}", self.size), Some("Size in bytes of this section"));
        dump.push_field("offset", format!("{:#x}", self.offset), Some("File offset of this section"));
        dump.push_field("align", format!("{:#x} (2^{})", 1u64 << self.align.min(63), self.align), Some("Section alignment (power of 2)"));
        dump.push_field("reloff", format!("{:#x}", self.reloff), Some("File offset of relocation entries"));
        dump.push_field("nreloc", format!("{}", self.nreloc), Some("Number of relocation entries"));
        dump.push_field("flags", format!("{:#x} ({})", self.flags, flags), Some("Flags (section type and attributes)"));
        dump.push_field("reserved1", format!("{:#x}", self.reserved1), Some("Reserved (for offset or index)"));
        dump.push_field("reserved2", format!("{:#x}", self.reserved2), Some("Reserved (for count or sizeof)"));
        dump.push_field("reserved3", format!("{:#x}", self.reserved3), Some("Reserved"));

        return dump;
    }
}

#[derive(Clone, Debug, Default)]
pub struct MachOSection {
    pub header: MachOSectionHeader,
    pub data: Vec<u8>,
}

impl MachOSection {
    pub fn contains_code(&self) -> bool {
        let code_attributes = SectionAttribute::SAttrPureInstructions as u32 | SectionAttribute::SAttrSomeInstructions as u32;

        return (self.header.flags & code_attributes) != 0;
    }

    pub fn dump(&self, binary: &MachOBinary, data: bool, disasm_code: bool) -> Dump {
        let mut dump = Dump::new_from_string(format!("Section ({})", self.header.full_name()));

        dump.push_child(self.header.dump());

        if disasm_code && self.contains_code() {
            if let Ok(code) = disasm_and_format_code(binary.architecture(), &self.data, self.header.addr) {
                dump.set_raw_data(DumpRawData::Code(code));
                return dump;
            }
        }

        if data {
            dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
        }

        return dump;
    }
}

/*
 * Load Command Data
 */

#[derive(Clone, Debug, Default)]
pub struct SegmentCommand {
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<MachOSectionHeader>,
}

impl SegmentCommand {
    pub fn from_reader(reader: &mut Reader, is_64: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut segment = Self::default();

        segment.segname = read_c_string(&reader.read_n::<16>()?, 0);

        if is_64 {
            segment.vmaddr = reader.read_u64()?;
            segment.vmsize = reader.read_u64()?;
            segment.fileoff = reader.read_u64()?;
            segment.filesize = reader.read_u64()?;
        } else {
            segment.vmaddr = reader.read_u32()? as u64;
            segment.vmsize = reader.read_u32()? as u64;
            segment.fileoff = reader.read_u32()? as u64;
            segment.filesize = reader.read_u32()? as u64;
        }

        segment.maxprot = reader.read_u32()?;
        segment.initprot = reader.read_u32()?;
        segment.nsects = reader.read_u32()?;
        segment.flags = reader.read_u32()?;

        for _ in 0..segment.nsects {
            segment.sections.push(MachOSectionHeader::from_reader(reader, is_64)?);
        }

        return Ok(segment);
    }
}

fn format_protection(prot: u32) -> String {
    return format!(
        "{}{}{}",
        if prot & 0x1 != 0 { "r" } else { "-" },
        if prot & 0x2 != 0 { "w" } else { "-" },
        if prot & 0x4 != 0 { "x" } else { "-" },
    );
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum Platform {
    MacOS = 1,
    IOS = 2,
    TvOS = 3,
    WatchOS = 4,
    BridgeOS = 5,
    MacCatalyst = 6,
    IOSSimulator = 7,
    TvOSSimulator = 8,
    WatchOSSimulator = 9,
    DriverKit = 10,
    VisionOS = 11,
    VisionOSSimulator = 12,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum BuildTool {
    Clang = 1,
    Swift = 2,
    Ld = 3,
    Lld = 4,
}

const DYSYMTAB_FIELDS: [&'static str; 18] = [
    "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym",
    "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms",
    "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel",
];

const DYLD_INFO_FIELDS: [&'static str; 10] = [
    "rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off",
    "weak_bind_size", "lazy_bind_off", "lazy_bind_size", "export_off", "export_size",
];

#[derive(Clone, Debug)]
pub enum LoadCommandData {
    Segment(SegmentCommand),
    Symtab { symoff: u32, nsyms: u32, stroff: u32, strsize: u32 },
    Dysymtab([u32; 18]),
    Dylib { name: String, timestamp: u32, current_version: u32, compatibility_version: u32 },
    Dylinker { name: String },
    Rpath { path: String },
    Main { entryoff: u64, stacksize: u64 },
    Uuid([u8; 16]),
    BuildVersion { platform: u32, minos: u32, sdk: u32, tools: Vec<(u32, u32)> },
    VersionMin { version: u32, sdk: u32 },
    SourceVersion(u64),
    LinkeditData { dataoff: u32, datasize: u32 },
    DyldInfo([u32; 10]),
    Raw,
}

#[derive(Clone, Debug)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data: LoadCommandData,
}

impl LoadCommand {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let start = reader.position();

        let cmd = reader.read_u32()?;
        let cmdsize = reader.read_u32()?;

        if cmdsize < 8 {
            return Err(format!("Invalid load command size {:#x} at offset {:#x}", cmdsize, start).into());
        }

        let command_bytes = {
            reader.set_position(start)?;
            let bytes = reader.read_bytes(cmdsize as usize)?.to_vec();
            reader.set_position(start + 8)?;
            bytes
        };

        let data = match LoadCommandType::from_repr(cmd) {
            Some(LoadCommandType::LcSegment) => LoadCommandData::Segment(SegmentCommand::from_reader(reader, false)?),
            Some(LoadCommandType::LcSegment64) => LoadCommandData::Segment(SegmentCommand::from_reader(reader, true)?),
            Some(LoadCommandType::LcSymtab) => LoadCommandData::Symtab {
                symoff: reader.read_u32()?,
                nsyms: reader.read_u32()?,
                stroff: reader.read_u32()?,
                strsize: reader.read_u32()?,
            },
            Some(LoadCommandType::LcDysymtab) => {
                let mut fields = [0u32; 18];

                for field in fields.iter_mut() {
                    *field = reader.read_u32()?;
                }

                LoadCommandData::Dysymtab(fields)
            }
            Some(LoadCommandType::LcLoadDylib | LoadCommandType::LcIdDylib | LoadCommandType::LcLoadWeakDylib |
                 LoadCommandType::LcReexportDylib | LoadCommandType::LcLazyLoadDylib | LoadCommandType::LcLoadUpwardDylib) => {
                let name_offset = reader.read_u32()?;

                LoadCommandData::Dylib {
                    name: read_c_string(&command_bytes, name_offset as usize),
                    timestamp: reader.read_u32()?,
                    current_version: reader.read_u32()?,
                    compatibility_version: reader.read_u32()?,
                }
            }
            Some(LoadCommandType::LcLoadDylinker | LoadCommandType::LcIdDylinker | LoadCommandType::LcDyldEnvironment) => {
                LoadCommandData::Dylinker { name: read_c_string(&command_bytes, reader.read_u32()? as usize) }
            }
            Some(LoadCommandType::LcRpath) => LoadCommandData::Rpath { path: read_c_string(&command_bytes, reader.read_u32()? as usize) },
            Some(LoadCommandType::LcMain) => LoadCommandData::Main { entryoff: reader.read_u64()?, stacksize: reader.read_u64()? },
            Some(LoadCommandType::LcUuid) => LoadCommandData::Uuid(reader.read_n::<16>()?),
            Some(LoadCommandType::LcBuildVersion) => {
                let platform = reader.read_u32()?;
                let minos = reader.read_u32()?;
                let sdk = reader.read_u32()?;
                let ntools = reader.read_u32()?;

                let mut tools = Vec::new();

                for _ in 0..ntools {
                    tools.push((reader.read_u32()?, reader.read_u32()?));
                }

                LoadCommandData::BuildVersion { platform, minos, sdk, tools }
            }
            Some(LoadCommandType::LcVersionMinMacosx | LoadCommandType::LcVersionMinIphoneos |
                 LoadCommandType::LcVersionMinTvos | LoadCommandType::LcVersionMinWatchos) => {
                LoadCommandData::VersionMin { version: reader.read_u32()?, sdk: reader.read_u32()? }
            }
            Some(LoadCommandType::LcSourceVersion) => LoadCommandData::SourceVersion(reader.read_u64()?),
            Some(LoadCommandType::LcCodeSignature | LoadCommandType::LcSegmentSplitInfo | LoadCommandType::LcFunctionStarts |
                 LoadCommandType::LcDataInCode | LoadCommandType::LcDylibCodeSignDrs | LoadCommandType::LcLinkerOptimizationHint |
                 LoadCommandType::LcDyldExportsTrie | LoadCommandType::LcDyldChainedFixups | LoadCommandType::LcAtomInfo) => {
                LoadCommandData::LinkeditData { dataoff: reader.read_u32()?, datasize: reader.read_u32()? }
            }
            Some(LoadCommandType::LcDyldInfo | LoadCommandType::LcDyldInfoOnly) => {
                let mut fields = [0u32; 10];

                for field in fields.iter_mut() {
                    *field = reader.read_u32()?;
                }

                LoadCommandData::DyldInfo(fields)
            }
            _ => LoadCommandData::Raw,
        };

        reader.set_position(start + cmdsize as usize)?;

        return Ok(Self { cmd, cmdsize, data });
    }

    pub fn name(&self) -> &'static str {
        return LoadCommandType::from_repr(self.cmd).map_or("LC_UNKNOWN", |c| c.into());
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new(self.name());

        dump.push_field("cmd", format!("{:#x}", self.cmd), None);
        dump.push_field("cmdsize", format!("{:#x}", self.cmdsize), None);

        match &self.data {
            LoadCommandData::Segment(segment) => {
                dump.push_field("segname", segment.segname.clone(), Some("Segment name"));
                dump.push_field("vmaddr", format!("{:#x}", segment.vmaddr), Some("Memory address of this segment"));
                dump.push_field("vmsize", format!("{:#x}", segment.vmsize), Some("Memory size of this segment"));
                dump.push_field("fileoff", format!("{:#x}", segment.fileoff), Some("File offset of this segment"));
                dump.push_field("filesize", format!("{:#x}", segment.filesize), Some("Amount to map from the file"));
                dump.push_field("maxprot", format!("{:#x} ({})", segment.maxprot, format_protection(segment.maxprot)), Some("Maximum VM protection"));
                dump.push_field("initprot", format!("{:#x} ({})", segment.initprot, format_protection(segment.initprot)), Some("Initial VM protection"));
                dump.push_field("nsects", format!("{}", segment.nsects), Some("Number of sections in segment"));
                dump.push_field("flags", format!("{:#x}", segment.flags), Some("Flags"));

                for section in segment.sections.iter() {
                    dump.push_child(section.dump());
                }
            }
            LoadCommandData::Symtab { symoff, nsyms, stroff, strsize } => {
                dump.push_field("symoff", format!("{:#x}", symoff), Some("Symbol table offset"));
                dump.push_field("nsyms", format!("{}", nsyms), Some("Number of symbol table entries"));
                dump.push_field("stroff", format!("{:#x}", stroff), Some("String table offset"));
                dump.push_field("strsize", format!("{:#x}", strsize), Some("String table size in bytes"));
            }
            LoadCommandData::Dysymtab(fields) => {
                for (name, value) in DYSYMTAB_FIELDS.iter().zip(fields.iter()) {
                    dump.push_field(name, format!("{:#x}", value), None);
                }
            }
            LoadCommandData::Dylib { name, timestamp, current_version, compatibility_version } => {
                dump.push_field("name", name.clone(), Some("Library path name"));
                dump.push_field("timestamp", format!("{:#x}", timestamp), Some("Library build time stamp"));
                dump.push_field("current_version", format_version(*current_version), Some("Library current version number"));
                dump.push_field("compatibility_version", format_version(*compatibility_version), Some("Library compatibility version number"));
            }
            LoadCommandData::Dylinker { name } => {
                dump.push_field("name", name.clone(), Some("Dynamic linker path name"));
            }
            LoadCommandData::Rpath { path } => {
                dump.push_field("path", path.clone(), Some("Path to add to run path"));
            }
            LoadCommandData::Main { entryoff, stacksize } => {
                dump.push_field("entryoff", format!("{:#x}", entryoff), Some("File (__TEXT) offset of main()"));
                dump.push_field("stacksize", format!("{:#x}", stacksize), Some("If not zero, initial stack size"));
            }
            LoadCommandData::Uuid(uuid) => {
                dump.push_field("uuid", uuid.iter().map(|b| format!("{:02X}", b)).collect::<String>(), Some("128-bit unique identifier"));
            }
            LoadCommandData::BuildVersion { platform, minos, sdk, tools } => {
                dump.push_field("platform", format!("{:#x} ({})", platform, Platform::from_repr(*platform).map_or("Unknown".to_string(), |p| format!("{:?}", p))), Some("Platform"));
                dump.push_field("minos", format_version(*minos), Some("Minimum OS version"));
                dump.push_field("sdk", format_version(*sdk), Some("SDK version"));

                for (tool, version) in tools.iter() {
                    dump.push_field("tool", format!("{} {}", BuildTool::from_repr(*tool).map_or(format!("{:#x}", tool), |t| format!("{:?}", t)), format_version(*version)), None);
                }
            }
            LoadCommandData::VersionMin { version, sdk } => {
                dump.push_field("version", format_version(*version), Some("Minimum OS version"));
                dump.push_field("sdk", format_version(*sdk), Some("SDK version"));
            }
            LoadCommandData::SourceVersion(version) => {
                let parts = [version >> 40, (version >> 30) & 0x3ff, (version >> 20) & 0x3ff, (version >> 10) & 0x3ff, version & 0x3ff];
                dump.push_field("version", parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("."), Some("A.B.C.D.E packed as a24.b10.c10.d10.e10"));
            }
            LoadCommandData::LinkeditData { dataoff, datasize } => {
                dump.push_field("dataoff", format!("{:#x}", dataoff), Some("File offset of data in __LINKEDIT segment"));
                dump.push_field("datasize", format!("{:#x}", datasize), Some("File size of data in __LINKEDIT segment"));
            }
            LoadCommandData::DyldInfo(fields) => {
                for (name, value) in DYLD_INFO_FIELDS.iter().zip(fields.iter()) {
                    dump.push_field(name, format!("{:#x}", value), None);
                }
            }
            LoadCommandData::Raw => {}
        }

        return dump;
    }
}

/*
 * Symbols (nlist)
 */

const N_STAB: u8 = 0xe0;
const N_PEXT: u8 = 0x10;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum SymbolType {
    Undf = 0x0,
    Abs = 0x2,
    Indr = 0xa,
    Pbud = 0xc,
    Sect = 0xe,
}

#[derive(Clone, Debug, Default)]
pub struct MachOSymbol {
    pub name: String,
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

impl MachOSymbol {
    pub fn from_reader(reader: &mut Reader, is_64: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut symbol = Self::default();

        symbol.n_strx = reader.read_u32()?;
        symbol.n_type = reader.read_u8()?;
        symbol.n_sect = reader.read_u8()?;
        symbol.n_desc = reader.read_u16()?;
        symbol.n_value = if is_64 { reader.read_u64()? } else { reader.read_u32()? as u64 };

        return Ok(symbol);
    }

    pub fn is_debug(&self) -> bool {
        return (self.n_type & N_STAB) != 0;
    }

    pub fn is_import(&self) -> bool {
        return !self.is_debug() && SymbolType::from_repr(self.n_type & N_TYPE) == Some(SymbolType::Undf) && (self.n_type & N_EXT) != 0;
    }

    pub fn type_as_string(&self) -> String {
        if self.is_debug() {
            return "Stab".to_string();
        }

        return SymbolType::from_repr(self.n_type & N_TYPE).map_or("Unknown".to_string(), |t| format!("{:?}", t));
    }

    pub fn scope_as_string(&self) -> &'static str {
        if (self.n_type & N_EXT) != 0 {
            return "Extern";
        }

        if (self.n_type & N_PEXT) != 0 {
            return "PrivExt";
        }

        return "Local";
    }

    pub fn demangled_name(&self) -> String {
        return self.name
            .strip_prefix('_')
            .and_then(|n| demangle(n).ok())
            .unwrap_or(self.name.clone());
    }

    pub fn as_string(&self) -> String {
        return format!(
            "{:#018x} {:<7} {:>4} {:<7} {}",
            self.n_value,
            self.type_as_string(),
            self.n_sect,
            self.scope_as_string(),
            self.demangled_name(),
        );
    }
}

/*
 * Mach-O Binary (a thin file or a slice of a fat file)
 */

#[derive(Clone, Debug, Default)]
pub struct MachOBinary {
    pub header: MachOHeader,
    pub load_commands: Vec<LoadCommand>,
    pub sections: HashMap<String, MachOSection>,
    pub symbols: Vec<MachOSymbol>,
}

impl MachOBinary {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() < 4 {
            return Err("File is too small to be a Mach-O file".into());
        }

        let mut reader = match u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) {
            MH_MAGIC | MH_MAGIC_64 => Reader::new_le(bytes),
            MH_CIGAM | MH_CIGAM_64 => Reader::new_be(bytes),
            _ => return Err("File magic number does not match Mach-O magic number".into()),
        };

        let mut binary = Self::default();

        binary.header = MachOHeader::from_reader(&mut reader)?;

        for _ in 0..binary.header.ncmds {
            binary.load_commands.push(LoadCommand::from_reader(&mut reader)?);
        }

        binary.parse_sections(&mut reader)?;
        binary.parse_symbols(&mut reader)?;

        return Ok(binary);
    }

    fn parse_sections(&mut self, reader: &mut Reader) -> Result<(), Box<dyn std::error::Error>> {
        for command in self.load_commands.iter() {
            if let LoadCommandData::Segment(segment) = &command.data {
                for header in segment.sections.iter() {
                    let mut section = MachOSection { header: header.clone(), data: Vec::new() };

                    if !header.is_zerofill() && header.size > 0 {
                        reader.set_position(header.offset as usize)?;
                        section.data = reader.read_bytes(header.size as usize)?.to_vec();
                    }

                    self.sections.insert(header.full_name(), section);
                }
            }
        }

        return Ok(());
    }

    fn parse_symbols(&mut self, reader: &mut Reader) -> Result<(), Box<dyn std::error::Error>> {
        let symtab = self.load_commands.iter().find_map(|c| match c.data {
            LoadCommandData::Symtab { symoff, nsyms, stroff, strsize } => Some((symoff, nsyms, stroff, strsize)),
            _ => None,
        });

        let Some((symoff, nsyms, stroff, strsize)) = symtab else {
            return Ok(());
        };

        reader.set_position(stroff as usize)?;
        let strtab = reader.read_bytes(strsize as usize)?.to_vec();

        reader.set_position(symoff as usize)?;

        for _ in 0..nsyms {
            let mut symbol = MachOSymbol::from_reader(reader, self.header.is_64())?;
            symbol.name = read_c_string(&strtab, symbol.n_strx as usize);
            self.symbols.push(symbol);
        }

        return Ok(());
    }

    pub fn cpu_name(&self) -> String {
        return cpu_name(self.header.cputype, self.header.cpusubtype);
    }

    pub fn architecture(&self) -> Architecture {
        match CpuType::from_repr(self.header.cputype) {
            Some(CpuType::X86) => Architecture::X86,
            Some(CpuType::X86_64) => Architecture::X86_64,
            Some(CpuType::Arm64 | CpuType::Arm64_32) => Architecture::Aarch64,
            _ => Architecture::Unsupported,
        }
    }

    pub fn dylibs(&self) -> Vec<&LoadCommand> {
        return self.load_commands
            .iter()
            .filter(|c| matches!(c.data, LoadCommandData::Dylib { .. }) && c.cmd != LoadCommandType::LcIdDylib as u32)
            .collect();
    }

    pub fn dump_load_commands(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Load Commands ({}, {})", self.cpu_name(), self.load_commands.len()));

        for command in self.load_commands.iter() {
            dump.push_child(command.dump());
        }

        return dump;
    }

    pub fn dump_symbols(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Symbol Table ({}, {} entries)", self.cpu_name(), self.symbols.len()));

        dump.push_field("", format!("{:<18} {:<7} {:>4} {:<7} {}", "Value", "Type", "Sect", "Scope", "Name"), None);

        for symbol in self.symbols.iter().filter(|s| !s.is_debug()) {
            dump.push_field("", symbol.as_string(), None);
        }

        return dump;
    }

    pub fn dump_dylibs(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Imports ({})", self.cpu_name()));

        for command in self.dylibs() {
            if let LoadCommandData::Dylib { name, current_version, .. } = &command.data {
                dump.push_field(command.name(), format!("{} ({})", name, format_version(*current_version)), None);
            }
        }

        for symbol in self.symbols.iter().filter(|s| s.is_import()) {
            dump.push_field("", symbol.demangled_name(), None);
        }

        return dump;
    }
}

/*
 * Mach-O
 */

#[derive(Clone, Debug, Default)]
pub struct MachO {
    pub fat_header: Option<FatHeader>,
    pub binaries: Vec<MachOBinary>,
}

pub fn parse_macho(file_path: &PathBuf) -> Result<MachO, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_bytes = std::fs::read(file_path)?;

    if !is_macho(&file_bytes) {
        return Err("File magic number does not match Mach-O magic number".into());
    }

    let mut macho = MachO::default();

    let magic = u32::from_be_bytes([file_bytes[0], file_bytes[1], file_bytes[2], file_bytes[3]]);

    if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
        let fat_header = FatHeader::from_reader(&mut Reader::new_be(&file_bytes))?;

        for arch in fat_header.archs.iter() {
            let start = arch.offset as usize;
            let end = start.checked_add(arch.size as usize).filter(|&e| e <= file_bytes.len());

            let Some(end) = end else {
                return Err(format!("Fat arch {} is out of the file bounds", cpu_name(arch.cputype, arch.cpusubtype)).into());
            };

            macho.binaries.push(MachOBinary::from_bytes(&file_bytes[start..end])?);
        }

        macho.fat_header = Some(fat_header);
    } else {
        macho.binaries.push(MachOBinary::from_bytes(&file_bytes)?);
    }

    return Ok(macho);
}
