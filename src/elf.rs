use crate::{disasm::disasm_elf_code, dump::{Dump, DumpRawData}, reader::{BEReader, LEReader, Reader}};

use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};

use std::{collections::HashMap, fmt::Display, ops::BitAnd, path::PathBuf};

pub const ELF_MAGIC: u32 = 0x7f454c46;
pub const ELF_MAGIC_ARRAY: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/*
 * ELF Class (32 or 64 bit, e_ident[EI_CLASS] in elf header)
 */

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFClass {
    ELF32,
    ELF64,
}

impl Default for ELFClass {
    fn default() -> Self {
        return Self::ELF64;
    }
}

impl TryFrom<u8> for ELFClass {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ELF32),
            2 => Ok(Self::ELF64),
            _ => Err(value),
        }
    }
}

/*
 * ELF Endianness (Little or Big, e_ident[EI_DATA] in elf header)
 */

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFEndianness {
    Little = 0x1,
    Big = 0x2,
}

impl From<u8> for ELFEndianness {
    fn from(value: u8) -> Self {
        return value.into();
    }
}

/*
 * ELF OS ABI (e_ident[EI_OSABI] in elf header)
 */

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFOsAbi {
    SystemV = 0x00,
    HPUX = 0x01,
    NetBSD = 0x02,
    Linux = 0x03,
    GNUHurd = 0x04,
    Solaris = 0x06,
    AIXMonterey = 0x07,
    IRIX = 0x08,
    FreeBSD = 0x09,
    Tru64 = 0x0A,
    NovellModesto = 0x0B,
    OpenBSD = 0x0C,
    OpenVMS = 0x0D,
    NonStopKernel = 0x0E,
    AROS = 0x0F,
    FenixOS = 0x10,
    NuxiCloudABI = 0x11,
    StratusTechnologiesOpenVOS = 0x12,
}

impl From<u8> for ELFOsAbi {
    fn from(value: u8) -> Self {
        return value.into();
    }
}

/*
 * Target ISA (e_machine in elf header)
 */

#[repr(u16)]
#[derive(Clone, Debug, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum ELFTargetISA {
    /// No specific instruction set
    Unknown = 0x00,
    ATnTWE32100 = 0x01,
    SPARC = 0x02,
    X86 = 0x03,
    Motorola68000 = 0x04,
    Motorola88000 = 0x05,
    IntelMCU = 0x06,
    Intel80860 = 0x07,
    MIPS = 0x08,
    IBMSystem370 = 0x09,
    MIPSRS3000LittleEndian = 0x0A,
    // 0x0B – 0x0E 	Reserved for future use
    HewlettPackardPARISC = 0x0F,
    Intel80960 = 0x13,
    PowerPC = 0x14,
    PowerPC64 = 0x15,
    S390 = 0x16,
    IBMSpuSpc = 0x17,
    // 0x18 – 0x23 	Reserved for future use
    NECV800 = 0x24,
    FujitsuFR20 = 0x25,
    TRWRH32 = 0x26,
    MotorolaRCE = 0x27,
    /// up to Armv7/AArch32
    Arm = 0x28,
    DigitalAlpha = 0x29,
    SuperH = 0x2A,
    SPARCVersion9 = 0x2B,
    SiemensTriCoreEmbeddedProcessor = 0x2C,
    ArgonautRISCCore = 0x2D,
    HitachiH8300 = 0x2E,
    HitachiH8300H = 0x2F,
    HitachiH8S = 0x30,
    HitachiH8500 = 0x31,
    IA64 = 0x32,
    StanfordMIPSX = 0x33,
    MotorolaColdFire = 0x34,
    MotorolaM68HC12 = 0x35,
    FujitsuMMAMultimediaAccelerator = 0x36,
    SiemensPCP = 0x37,
    SonynCPUEmbeddedRISCProcessor = 0x38,
    DensoNDR1MicroProcessor = 0x39,
    MotorolaStarCoreProcessor = 0x3A,
    ToyotaME16Processor = 0x3B,
    STMicroelectronicsST100Processor = 0x3C,
    AdvancedLogicCorpTinyJEmbeddedProcessorFamily = 0x3D,
    AMDX86_64 = 0x3E,
    SonyDSPProcessor = 0x3F,
    DigitalEquipmentCorpPDP10 = 0x40,
    DigitalEquipmentCorpPDP11 = 0x41,
    SiemensFX66MicroController = 0x42,
    STMicroelectronicsST98_16BitMicroController = 0x43,
    STMicroelectronicsST7_8BitMicroController = 0x44,
    MotorolaMC68HC16Microcontroller = 0x45,
    MotorolaMC68HC11Microcontroller = 0x46,
    MotorolaMC68HC08Microcontroller = 0x47,
    MotorolaMC68HC05Microcontroller = 0x48,
    SiliconGraphicsSVx = 0x49,
    STMicroelectronicsST19_8bitMicroController = 0x4A,
    DigitalVAX = 0x4B,
    AxisCommunications32bitEmbeddedProcessor = 0x4C,
    InfineonTechnologies32bitEmbeddedProcessor = 0x4D,
    Element1464bitDSPProcessor = 0x4E,
    LSILogic16bitDSPProcessor = 0x4F,
    TMS320C6000Family = 0x8C,
    MCSTElbrusE2k = 0xAF,
    Arm64bits = 0xB7,
    ZilogZ80 = 0xDC,
    RISCV = 0xF3,
    BerkeleyPacketFilter = 0xF7,
    WDC65C816 = 0x101,
    LoongArch = 0x102,
}

/*
 * Elf File Type (e_type in elf header)
 */

#[repr(u16)]
#[derive(Clone, Debug)]
pub enum ELFFileType {
    /// Unknown.
    ETNone = 0x00,
    /// Relocatable file.
    ETRel = 0x01,
    /// Executable file.
    ETExec = 0x02,
    /// Shared object.
    ETDyn = 0x03,
    /// Core file.
    ETCore = 0x04,
    /// Reserved inclusive range. Operating system specific.
    ETLoOs = 0xFE00,
    /// Reserved inclusive range. Operating system specific.
    ETHiOs = 0xFEFF,
    /// Reserved inclusive range. Processor specific.
    ETLoProc = 0xFF00,
    /// Reserved inclusive range. Processor specific.
    ETHiProc = 0xFFFF,
}

impl From<u16> for ELFFileType {
    fn from(value: u16) -> Self {
        match value {
             0x00 => Self::ETNone,
             0x01 => Self::ETRel,
             0x02 => Self::ETExec,
             0x03 => Self::ETDyn,
             0x04 => Self::ETCore,
             0xFE00..0xFEFF => Self::ETLoOs,
             0xFEFF => Self::ETHiOs,
             0xFF00..0xFFFF => Self::ETLoProc,
             0xFFFF => Self::ETHiProc,
             _ => Self::ETNone,

        }
    }
}

impl Display for ELFFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ETNone => write!(f, "{:?} (Unknown)", self),
            Self::ETRel => write!(f, "{:?} (Relocatable file)", self),
            Self::ETExec => write!(f, "{:?} (Executable file)", self),
            Self::ETDyn => write!(f, "{:?} (Shared object)", self),
            Self::ETCore => write!(f, "{:?} (Core file)", self),
            Self::ETLoOs => write!(f, "{:?} (Reserved inclusive range. Operating system specific)", self),
            Self::ETHiOs => write!(f, "{:?} (Reserved inclusive range. Operating system specific)", self),
            Self::ETLoProc => write!(f, "{:?} (Reserved inclusive range. Processor specific)", self),
            Self::ETHiProc => write!(f, "{:?} (Reserved inclusive range. Processor specific)", self),
        }
    }
}

/* ELF Header */

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFHeader32 {
    /// 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    ei_mag: [u8; 4],

    /// This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    ei_class: u8,

    /// This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
    ei_data: u8,

    ///j Set to 1 for the original and current version of ELF.
    ei_version: u8,

    /// Identifies the target operating system ABI.
    ei_osabi: u8,

    /// Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]
    ei_abiversion: u8,

    /// Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read.
    ei_pad: [u8; 7],

    /// Identifies object file type.
    e_type: u16,

    /// Specifies target instruction set architecture.
    e_machine: u16,

    /// Set to 1 for the original version of ELF.
    e_version: u32,

    /// This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero.
    e_entry: u32,

    /// Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
    e_phoff: u32,

    /// Points to the start of the section header table.
    e_shoff: u32,

    /// Interpretation of this field depends on the target architecture.
    e_flags: u32,

    /// Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
    e_ehsize: u16,

    /// Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit).
    e_phentsize: u16,

    /// Contains the number of entries in the program header table.
    e_phnum: u16,

    /// Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit).
    e_shentsize: u16,

    /// Contains the number of entries in the section header table.
    e_shnum: u16,

    /// Contains index of the section header table entry that contains the section names.
    e_shstrndx: u16,
}

impl ELFHeader32 {
    pub fn from_parser(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.ei_mag = reader.read_n()?;
        header.ei_class = reader.read_u8()?;
        header.ei_data = reader.read_u8()?;
        header.ei_version = reader.read_u8()?;
        header.ei_osabi = reader.read_u8()?;
        header.ei_abiversion = reader.read_u8()?;
        header.ei_pad = reader.read_n()?;
        header.e_type = reader.read_u16()?;
        header.e_machine = reader.read_u16()?;
        header.e_version = reader.read_u32()?;
        header.e_entry = reader.read_u32()?;
        header.e_phoff = reader.read_u32()?;
        header.e_shoff = reader.read_u32()?;
        header.e_flags = reader.read_u32()?;
        header.e_ehsize = reader.read_u16()?;
        header.e_phentsize = reader.read_u16()?;
        header.e_phnum = reader.read_u16()?;
        header.e_shentsize = reader.read_u16()?;
        header.e_shnum = reader.read_u16()?;
        header.e_shstrndx = reader.read_u16()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("ELF Header (32-bit)");

        dump.push_field("ei_magic", format!("{:#x}, {}, {}, {}", self.ei_mag[0], self.ei_mag[1] as char, self.ei_mag[2] as char, self.ei_mag[3] as char), Some("ELF Magic number"));
        dump.push_field("ei_class", format!("{:#x}", self.ei_class), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x}", self.ei_data), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x}", self.ei_osabi), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{}", ELFFileType::from(self.e_type)), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x}", self.e_machine), Some("Specifies target instruction set architecture."));
        dump.push_field("e_version", format!("{:#x}", self.e_version), Some("Set to 1 for the original version of ELF."));
        dump.push_field("e_entry", format!("{:#x}", self.e_entry), Some("This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero."));
        dump.push_field("e_phoff", format!("{:#x}", self.e_phoff), Some("Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively."));
        dump.push_field("e_shoff", format!("{:#x}", self.e_shoff), Some("Points to the start of the section header table."));
        dump.push_field("e_flags", format!("{:#x}", self.e_flags), Some("Interpretation of this field depends on the target architecture."));
        dump.push_field("e_ehsize", format!("{:#x}", self.e_ehsize), Some("Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format."));
        dump.push_field("e_phentsize", format!("{:#x}", self.e_phentsize), Some("Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit)."));
        dump.push_field("e_phnum", format!("{:#x}", self.e_phnum), Some("Contains the number of entries in the program header table."));
        dump.push_field("e_shentsize", format!("{:#x}", self.e_shentsize), Some("Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit)."));
        dump.push_field("e_shnum", format!("{:#x}", self.e_shnum), Some("Contains the number of entries in the section header table."));
        dump.push_field("e_shstrndx", format!("{:#x}", self.e_shstrndx), Some("Contains index of the section header table entry that contains the section names."));

        return dump;
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFHeader64 {
    /// 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    ei_mag: [u8; 4],

    /// This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    ei_class: u8,

    /// This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
    ei_data: u8,
    ///j Set to 1 for the original and current version of ELF.
    ei_version: u8,

    /// Identifies the target operating system ABI.
    ei_osabi: u8,

    /// Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]
    ei_abiversion: u8,

    /// Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read.
    ei_pad: [u8; 7],

    /// Identifies object file type.
    e_type: u16,

    /// Specifies target instruction set architecture.
    e_machine: u16,

    /// Set to 1 for the original version of ELF.
    e_version: u32,

    /// This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero.
    e_entry: u64,

    /// Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
    e_phoff: u64,

    /// Points to the start of the section header table.
    e_shoff: u64,

    /// Interpretation of this field depends on the target architecture.
    e_flags: u32,

    /// Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
    e_ehsize: u16,

    /// Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit).
    e_phentsize: u16,

    /// Contains the number of entries in the program header table.
    e_phnum: u16,

    /// Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit).
    e_shentsize: u16,

    /// Contains the number of entries in the section header table.
    e_shnum: u16,

    /// Contains index of the section header table entry that contains the section names.
    e_shstrndx: u16,
}

impl ELFHeader64 {
    pub fn from_parser(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.ei_mag = reader.read_n()?;
        header.ei_class = reader.read_u8()?;
        header.ei_data = reader.read_u8()?;
        header.ei_version = reader.read_u8()?;
        header.ei_osabi = reader.read_u8()?;
        header.ei_abiversion = reader.read_u8()?;
        header.ei_pad = reader.read_n()?;
        header.e_type = reader.read_u16()?;
        header.e_machine = reader.read_u16()?;
        header.e_version = reader.read_u32()?;
        header.e_entry = reader.read_u64()?;
        header.e_phoff = reader.read_u64()?;
        header.e_shoff = reader.read_u64()?;
        header.e_flags = reader.read_u32()?;
        header.e_ehsize = reader.read_u16()?;
        header.e_phentsize = reader.read_u16()?;
        header.e_phnum = reader.read_u16()?;
        header.e_shentsize = reader.read_u16()?;
        header.e_shnum = reader.read_u16()?;
        header.e_shstrndx = reader.read_u16()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("ELF Header (64-bit)");

        dump.push_field("ei_magic", format!("{:#x}, {}, {}, {}", self.ei_mag[0], self.ei_mag[1] as char, self.ei_mag[2] as char, self.ei_mag[3] as char), Some("ELF Magic number"));
        dump.push_field("ei_class", format!("{:#x}", self.ei_class), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x}", self.ei_data), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x}", self.ei_osabi), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{:#x}", self.e_type), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x}", self.e_machine), Some("Specifies target instruction set architecture."));
        dump.push_field("e_version", format!("{:#x}", self.e_version), Some("Set to 1 for the original version of ELF."));
        dump.push_field("e_entry", format!("{:#x}", self.e_entry), Some("This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero."));
        dump.push_field("e_phoff", format!("{:#x}", self.e_phoff), Some("Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively."));
        dump.push_field("e_shoff", format!("{:#x}", self.e_shoff), Some("Points to the start of the section header table."));
        dump.push_field("e_flags", format!("{:#x}", self.e_flags), Some("Interpretation of this field depends on the target architecture."));
        dump.push_field("e_ehsize", format!("{:#x}", self.e_ehsize), Some("Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format."));
        dump.push_field("e_phentsize", format!("{:#x}", self.e_phentsize), Some("Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit)."));
        dump.push_field("e_phnum", format!("{:#x}", self.e_phnum), Some("Contains the number of entries in the program header table."));
        dump.push_field("e_shentsize", format!("{:#x}", self.e_shentsize), Some("Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit)."));
        dump.push_field("e_shnum", format!("{:#x}", self.e_shnum), Some("Contains the number of entries in the section header table."));
        dump.push_field("e_shstrndx", format!("{:#x}", self.e_shstrndx), Some("Contains index of the section header table entry that contains the section names."));

        return dump;
    }
}

#[derive(Clone, Debug)]
pub enum ELFHeader {
    ELFHeader32(ELFHeader32),
    ELFHeader64(ELFHeader64),
}

impl Default for ELFHeader {
    fn default() -> Self {
        return Self::ELFHeader64(ELFHeader64::default());
    }
}

impl ELFHeader {
    pub fn from_parser(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let class_byte = reader.peek_at::<4>()?;

        match class_byte {
            1 => Ok(Self::ELFHeader32(ELFHeader32::from_parser(reader)?)),
            2 => Ok(Self::ELFHeader64(ELFHeader64::from_parser(reader)?)),
            _ => Err("Invalid ELF Class".into()),
        }
    }

    pub fn program_headers_offset(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_phoff as u64,
            Self::ELFHeader64(h) => h.e_phoff,
        }
    }

    pub fn program_headers_num_entries(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_phnum as u64,
            Self::ELFHeader64(h) => h.e_phnum as u64,
        }
    }

    pub fn program_headers_entry_sz(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_phentsize as u64,
            Self::ELFHeader64(h) => h.e_phentsize as u64,
        }
    }

    pub fn section_headers_offset(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_shoff as u64,
            Self::ELFHeader64(h) => h.e_shoff,
        }
    }

    pub fn section_headers_num_entries(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_shnum as u64,
            Self::ELFHeader64(h) => h.e_shnum as u64,
        }
    }

    pub fn section_headers_entry_sz(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_shentsize as u64,
            Self::ELFHeader64(h) => h.e_shentsize as u64,
        }
    }

    pub fn shstr_index(&self) -> usize {
        match self {
            Self::ELFHeader32(h) => h.e_shstrndx as usize,
            Self::ELFHeader64(h) => h.e_shstrndx as usize,
        }
    }

    pub fn dump(&self) -> Dump {
        match self {
            Self::ELFHeader32(h) => h.dump(),
            Self::ELFHeader64(h) => h.dump(),
        }
    }
}

/*
 * Segment Type (p_type in program header)
 */

 #[repr(u32)]
 #[derive(Clone, Copy, Debug, PartialEq, Eq)]
 pub enum ProgramHeaderType {
     /// Program header table entry unused (0)
     Null = 0x00000000,

     /// Loadable segment (1)
     Load = 0x00000001,

     /// Dynamic linking information (2)
     Dynamic = 0x00000002,

     /// Interpreter information (required for dynamically linked executables) (3)
     Interp = 0x00000003,

     /// Auxiliary information (4)
     Note = 0x00000004,

     /// Reserved (5)
     Shlib = 0x00000005,

     /// Segment containing the program header table itself (6)
     Phdr = 0x00000006,

     /// Thread-Local Storage template (7)
     Tls = 0x00000007,

     // GNU/Linux extended segment types (OS-specific, range 0x60000000+)
     // Most common ones

     /// GNU exception handling frame header (.eh_frame_hdr) (0x6474e550)
     GnuEhFrame = 0x6474e550,

     /// GNU stack permissions (often RW or R only) (0x6474e551)
     GnuStack = 0x6474e551,

     /// GNU RELRO (read-only after relocation) (0x6474e552)
     GnuRelro = 0x6474e552,

     /// GNU property note (Intel CET, branch protection...) (0x6474e553)
     GnuProperty = 0x6474e553,

     /// ARM unwind segment (very rare outside ARM)
     ArmExIdx = 0x70000001,

     /// Solaris-specific
     SunwUnwind = 0x6ffffffb,
     SunwStack = 0x6ffffffa,

     /// Architecture-specific range start/end
     LoOs = 0x60000000,
     HiOs = 0x6fffffff,
     LoProc = 0x70000000,
     HiProc = 0xffffffff,
 }

 impl From<u32> for ProgramHeaderType {
     fn from(value: u32) -> Self {
         match value {
             0x00000000 => Self::Null,
             0x00000001 => Self::Load,
             0x00000002 => Self::Dynamic,
             0x00000003 => Self::Interp,
             0x00000004 => Self::Note,
             0x00000005 => Self::Shlib,
             0x00000006 => Self::Phdr,
             0x00000007 => Self::Tls,

             0x6474e550 => Self::GnuEhFrame,
             0x6474e551 => Self::GnuStack,
             0x6474e552 => Self::GnuRelro,
             0x6474e553 => Self::GnuProperty,

             0x70000001 => Self::ArmExIdx,

             _ => Self::Null,
         }
     }
 }

 impl std::fmt::Display for ProgramHeaderType {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             Self::Null          => write!(f, "PT_NULL - unused"),
             Self::Load          => write!(f, "PT_LOAD - Loadable segment"),
             Self::Dynamic       => write!(f, "PT_DYNAMIC - Dynamic linking information"),
             Self::Interp        => write!(f, "PT_INTERP - Program interpreter (dynamic linker)"),
             Self::Note          => write!(f, "PT_NOTE - Auxiliary information (notes)"),
             Self::Shlib         => write!(f, "PT_SHLIB - Reserved"),
             Self::Phdr          => write!(f, "PT_PHDR - Program header table itself"),
             Self::Tls           => write!(f, "PT_TLS - Thread-Local Storage template"),

             Self::GnuEhFrame    => write!(f, "PT_GNU_EH_FRAME - Exception handling frame header"),
             Self::GnuStack      => write!(f, "PT_GNU_STACK - Stack permissions"),
             Self::GnuRelro      => write!(f, "PT_GNU_RELRO - Read-only after relocation (RELRO)"),
             Self::GnuProperty   => write!(f, "PT_GNU_PROPERTY - GNU property note (x86 CET, BTI, etc)"),

             Self::ArmExIdx      => write!(f, "PT_ARM_EXIDX - ARM unwind information"),

             Self::SunwUnwind    => write!(f, "PT_SUNW_UNWIND - Solaris unwind info"),
             Self::SunwStack     => write!(f, "PT_SUNW_STACK - Solaris stack info"),

             _ => write!(f, "OS/Architecture Specific"),
         }
     }
 }

/*
 * Segment-Dependent Flags (p_flags in program header)
 */

#[repr(u32)]
#[derive(Clone, Debug, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum ProgramHeaderFlag {
    /// Executable segment
    PfExecutable = 0x1,
    /// Writeable segment
    PfWritable = 0x2,
    /// Readable segment
    PfReadable = 0x4,
}

impl ProgramHeaderFlag {
    pub fn flags_as_string(flags: u32) -> String {
        let str_flags: Vec<&'static str> = ProgramHeaderFlag::iter()
            .filter(|&flag| (flag as u32 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return str_flags.join(" | ");
    }
}

/*
 * Program Header
 */

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFProgramHeader32 {
    /// Identifies the type of the segment.
    p_type: u32,

    /// Offset of the segment in the file image.
    p_offset: u32,

    /// Virtual address of the segment in memory.
    p_vaddr: u32,

    /// On systems where physical address is relevant, reserved for segment's physical address.
    p_paddr: u32,

    /// Size in bytes of the segment in the file image. May be 0.
    p_filesz: u32,

    /// Size in bytes of the segment in memory. May be 0.
    p_memsz: u32,

    /// Segment-dependent flags. See above p_flags field for flag definitions.
    p_flags: u32,

    /// 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
    p_align: u32,
}

impl ELFProgramHeader32 {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.p_type = reader.read_u32()?;
        header.p_offset = reader.read_u32()?;
        header.p_vaddr = reader.read_u32()?;
        header.p_paddr = reader.read_u32()?;
        header.p_filesz = reader.read_u32()?;
        header.p_memsz = reader.read_u32()?;
        header.p_flags = reader.read_u32()?;
        header.p_align = reader.read_u32()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Program Header (32-bit)");

        dump.push_field("p_type", format!("{:#x} ({})", self.p_type, ProgramHeaderType::from(self.p_type)), Some("Identifies the type of the segment"));
        dump.push_field("p_offset", format!("{:#x}", self.p_offset), Some("Offset of the segment in the file image"));
        dump.push_field("p_vaddr", format!("{:#x}", self.p_vaddr), Some("Virtual address of the segment in memory"));
        dump.push_field("p_paddr", format!("{:#x}", self.p_paddr), Some("On systems where physical address is relevant, reserved for segment's physical address"));
        dump.push_field("p_filesz", format!("{:#x}", self.p_filesz), Some("Size in bytes of the segment in the file image. May be 0"));
        dump.push_field("p_memsz", format!("{:#x}", self.p_memsz), Some("Size in bytes of the segment in memory. May be 0"));
        dump.push_field("p_flags", format!("{:#x} ({})", self.p_flags, ProgramHeaderFlag::flags_as_string(self.p_flags)), Some("Segment-dependent flags"));
        dump.push_field("p_align", format!("{:#x}", self.p_align), Some("0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align"));

        return dump;
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFProgramHeader64 {
    /// Identifies the type of the segment.
    p_type: u32,

    /// Segment-dependent flags. See above p_flags field for flag definitions.
    p_flags: u32,

    /// Offset of the segment in the file image.
    p_offset: u64,

    /// Virtual address of the segment in memory.
    p_vaddr: u64,

    /// On systems where physical address is relevant, reserved for segment's physical address.
    p_paddr: u64,

    /// Size in bytes of the segment in the file image. May be 0.
    p_filesz: u64,

    /// Size in bytes of the segment in memory. May be 0.
    p_memsz: u64,

    /// 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
    p_align: u64,
}

impl ELFProgramHeader64 {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.p_type = reader.read_u32()?;
        header.p_flags = reader.read_u32()?;
        header.p_offset = reader.read_u64()?;
        header.p_vaddr = reader.read_u64()?;
        header.p_paddr = reader.read_u64()?;
        header.p_filesz = reader.read_u64()?;
        header.p_memsz = reader.read_u64()?;
        header.p_align = reader.read_u64()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Program Header (64-bit)");

        dump.push_field("p_type", format!("{:#x} ({})", self.p_type, ProgramHeaderType::from(self.p_type)), Some("Identifies the type of the segment"));
        dump.push_field("p_flags", format!("{:#x} ({})", self.p_flags, ProgramHeaderFlag::flags_as_string(self.p_flags)), Some("Segment-dependent flags"));
        dump.push_field("p_offset", format!("{:#x}", self.p_offset), Some("Offset of the segment in the file image"));
        dump.push_field("p_vaddr", format!("{:#x}", self.p_vaddr), Some("Virtual address of the segment in memory"));
        dump.push_field("p_paddr", format!("{:#x}", self.p_paddr), Some("On systems where physical address is relevant, reserved for segment's physical address"));
        dump.push_field("p_filesz", format!("{:#x}", self.p_filesz), Some("Size in bytes of the segment in the file image. May be 0"));
        dump.push_field("p_memsz", format!("{:#x}", self.p_memsz), Some("Size in bytes of the segment in memory. May be 0"));
        dump.push_field("p_align", format!("{:#x}", self.p_align), Some("0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align"));

        return dump;
    }
}

#[derive(Clone, Debug)]
pub enum ELFProgramHeader {
    ELFProgramHeader32(ELFProgramHeader32),
    ELFProgramHeader64(ELFProgramHeader64),
}

impl ELFProgramHeader {
    pub fn dump(&self) -> Dump {
        match self {
            Self::ELFProgramHeader32(h) => h.dump(),
            Self::ELFProgramHeader64(h) => h.dump(),
        }
    }
}

/*
 * Section Flags
 */

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionFlags {
    NoFlags = 0x0,
    Write = 0x1,
    Alloc = 0x2,
    ExecInstr = 0x4,
    Merge = 0x10,
    Strings = 0x20,
    InfoLink = 0x40,
    LinkOrder = 0x80,
    OsNonconforming = 0x100,
    Group = 0x200,
    TLS = 0x400,
    Ordered = 0x4000000,
    Exclude = 0x8000000,
}

impl SectionFlags {
    pub fn flags_as_string(flags: u64) -> String {
        let flags_str: Vec<&'static str> = SectionFlags::iter()
            .filter(|&flag| (flag as u64 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags_str.join(" | ");
    }

    pub fn contains(self, rhs: Self) -> bool {
        return (self as u64 & rhs as u64) != 0;
    }
}

/*
 * Section Type
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionType {
    /// Section header table entry unused
    Null              = 0x00,

    /// Program data (code, initialized data...)
    Progbits          = 0x01,

    /// Symbol table
    Symtab            = 0x02,

    /// String table
    Strtab            = 0x03,

    /// Relocation entries with explicit addends
    Rela              = 0x04,

    /// Symbol hash table
    Hash              = 0x05,

    /// Dynamic linking information (.dynamic section)
    Dynamic           = 0x06,

    /// Notes section (build-id, ABI tag..)
    Note              = 0x07,

    /// Program space with no data in file (BSS)
    Nobits            = 0x08,

    /// Relocation entries without addends
    Rel               = 0x09,

    /// Reserved (historically used by some systems)
    Shlib             = 0x0A,

    /// Dynamic linker symbol table (usually only exported symbols)
    Dynsym            = 0x0B,

    /// Array of constructors (.ctors / .init_array)
    InitArray         = 0x0E,

    /// Array of destructors (.dtors / .fini_array)
    FiniArray         = 0x0F,

    /// Array of pre-initializers (.preinit_array)
    PreinitArray      = 0x10,

    /// Section group (COMDAT, etc.)
    Group             = 0x11,

    /// Extended section indices (for huge object files)
    SymtabShndx       = 0x12,

    /// Number of defined types (not really a section type)
    Num               = 0x13,

    /// GNU exception handling frame information (.eh_frame_hdr)
    GnuEhFrame        = 0x6ffffffb,

    /// GNU version definitions
    GnuVerdef         = 0x6ffffffd,

    /// GNU version needs/requirements
    GnuVerneed        = 0x6ffffffe,

    /// GNU symbol version table
    GnuVersym         = 0x6fffffff,

    /// GNU hash table (faster than classic .hash)
    GnuHash           = 0x6ffffff6,
}

impl From<u32> for SectionType {
    fn from(value: u32) -> Self {
        match value {
            0x00 => SectionType::Null,
            0x01 => SectionType::Progbits,
            0x02 => SectionType::Symtab,
            0x03 => SectionType::Strtab,
            0x04 => SectionType::Rela,
            0x05 => SectionType::Hash,
            0x06 => SectionType::Dynamic,
            0x07 => SectionType::Note,
            0x08 => SectionType::Nobits,
            0x09 => SectionType::Rel,
            0x0A => SectionType::Shlib,
            0x0B => SectionType::Dynsym,
            0x0E => SectionType::InitArray,
            0x0F => SectionType::FiniArray,
            0x10 => SectionType::PreinitArray,
            0x11 => SectionType::Group,
            0x12 => SectionType::SymtabShndx,
            0x13 => SectionType::Num,
            0x6ffffff6 => SectionType::GnuHash,
            0x6ffffffb => SectionType::GnuEhFrame,
            0x6ffffffd => SectionType::GnuVerdef,
            0x6ffffffe => SectionType::GnuVerneed,
            0x6fffffff => SectionType::GnuVersym,
            _ => SectionType::Null,
        }
    }
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionType::Null => write!(f, "SHT_NULL"),
            SectionType::Progbits => write!(f, "SHT_PROGBITS"),
            SectionType::Symtab => write!(f, "SHT_SYMTAB"),
            SectionType::Strtab => write!(f, "SHT_STRTAB"),
            SectionType::Rela => write!(f, "SHT_RELA"),
            SectionType::Hash => write!(f, "SHT_HASH"),
            SectionType::Dynamic => write!(f, "SHT_DYNAMIC"),
            SectionType::Note => write!(f, "SHT_NOTE"),
            SectionType::Nobits => write!(f, "SHT_NOBITS"),
            SectionType::Rel => write!(f, "SHT_REL"),
            SectionType::Shlib => write!(f, "SHT_SHLIB"),
            SectionType::Dynsym => write!(f, "SHT_DYNSYM"),
            SectionType::InitArray => write!(f, "SHT_INIT_ARRAY"),
            SectionType::FiniArray => write!(f, "SHT_FINI_ARRAY"),
            SectionType::PreinitArray => write!(f, "SHT_PREINIT_ARRAY"),
            SectionType::Group => write!(f, "SHT_GROUP"),
            SectionType::SymtabShndx => write!(f, "SHT_SYMTAB_SHNDX"),
            SectionType::GnuHash => write!(f, "SHT_GNU_HASH"),
            SectionType::GnuEhFrame => write!(f, "SHT_GNU_EH_FRAME"),
            SectionType::GnuVerdef => write!(f, "SHT_GNU_VERDEF"),
            SectionType::GnuVerneed => write!(f, "SHT_GNU_VERNEED"),
            SectionType::GnuVersym => write!(f, "SHT_GNU_VERSYM"),
            SectionType::Num => write!(f, "SHT_NUM"),
            _ => write!(f, "OS/Architecture specific")
        }
    }
}

/*
 * Section Header
 */

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFSectionHeader32 {
    /// An offset to a string in the .shstrtab section that represents the name of this section
    sh_name: u32,

    /// Identifies the type of this header
    sh_type: u32,

    /// Identifies the attributes of the section
    sh_flags: u32,

    /// Virtual address of the section in memory, for sections that are loaded
    sh_addr: u32,

    /// Offset of the section in the file image
    sh_offset: u32,

    /// Size in bytes of the section. May be 0
    sh_size: u32,

    /// Contains the section index of an associated section. This field is used for several purposes, depending on the type of section
    sh_link: u32,

    /// Contains extra information about the section. This field is used for several purposes, depending on the type of section
    sh_info: u32,

    /// Contains the required alignment of the section. This field must be a power of two
    sh_addralign: u32,

    /// Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero.
    sh_entsize: u32,
}

impl ELFSectionHeader32 {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.sh_name = reader.read_u32()?;
        header.sh_type = reader.read_u32()?;
        header.sh_flags = reader.read_u32()?;
        header.sh_addr = reader.read_u32()?;
        header.sh_offset = reader.read_u32()?;
        header.sh_size = reader.read_u32()?;
        header.sh_link = reader.read_u32()?;
        header.sh_info = reader.read_u32()?;
        header.sh_addralign = reader.read_u32()?;
        header.sh_entsize = reader.read_u32()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Section Header (32-bit)");

        dump.push_field("sh_name", format!("{:#x}", self.sh_name), Some("An offset to a string in the .shstrtab section that represents the name of this section"));
        dump.push_field("sh_type", format!("{:#x} ({})", self.sh_type, SectionType::from(self.sh_type)), Some("Identifies the type of this header"));
        dump.push_field("sh_flags", format!("{:#x} ({})", self.sh_flags, SectionFlags::flags_as_string(self.sh_flags as u64)), Some("Identifies the attributes of the section"));
        dump.push_field("sh_addr", format!("{:#x}", self.sh_addr), Some("Virtual address of the section in memory, for sections that are loaded"));
        dump.push_field("sh_offset", format!("{:#x}", self.sh_offset), Some("Offset of the section in the file image"));
        dump.push_field("sh_size", format!("{:#x}", self.sh_size), Some("Size in bytes of the section. May be 0"));
        dump.push_field("sh_link", format!("{:#x}", self.sh_link), Some("Contains the section index of an associated section. This field is used for several purposes, depending on the type of section"));
        dump.push_field("sh_info", format!("{:#x}", self.sh_info), Some("Contains extra information about the section. This field is used for several purposes, depending on the type of section"));
        dump.push_field("sh_addralign", format!("{:#x}", self.sh_addralign), Some("Contains the required alignment of the section. This field must be a power of two"));
        dump.push_field("sh_entsize", format!("{:#x}", self.sh_entsize), Some("Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero."));

        return dump;
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ELFSectionHeader64 {
    /// An offset to a string in the .shstrtab section that represents the name of this section
    sh_name: u32,

    /// Identifies the type of this header
    sh_type: u32,

    /// Identifies the attributes of the section
    sh_flags: u64,

    /// Virtual address of the section in memory, for sections that are loaded
    sh_addr: u64,

    /// Offset of the section in the file image
    sh_offset: u64,

    /// Size in bytes of the section. May be 0
    sh_size: u64,

    /// Contains the section index of an associated section. This field is used for several purposes, depending on the type of section
    sh_link: u32,

    /// Contains extra information about the section. This field is used for several purposes, depending on the type of section
    sh_info: u32,

    /// Contains the required alignment of the section. This field must be a power of two
    sh_addralign: u64,

    /// Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero.
    sh_entsize: u64,
}

impl ELFSectionHeader64 {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut header = Self::default();

        header.sh_name = reader.read_u32()?;
        header.sh_type = reader.read_u32()?;
        header.sh_flags = reader.read_u64()?;
        header.sh_addr = reader.read_u64()?;
        header.sh_offset = reader.read_u64()?;
        header.sh_size = reader.read_u64()?;
        header.sh_link = reader.read_u32()?;
        header.sh_info = reader.read_u32()?;
        header.sh_addralign = reader.read_u64()?;
        header.sh_entsize = reader.read_u64()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Section Header (64-bit)");

        dump.push_field("sh_name", format!("{:#x}", self.sh_name), Some("An offset to a string in the .shstrtab section that represents the name of this section"));
        dump.push_field("sh_type", format!("{:#x} ({})", self.sh_type, SectionType::from(self.sh_type)), Some("Identifies the type of this header"));
        dump.push_field("sh_flags", format!("{:#x} ({})", self.sh_flags, SectionFlags::flags_as_string(self.sh_flags)), Some("Identifies the attributes of the section"));
        dump.push_field("sh_addr", format!("{:#x}", self.sh_addr), Some("Virtual address of the section in memory, for sections that are loaded"));
        dump.push_field("sh_offset", format!("{:#x}", self.sh_offset), Some("Offset of the section in the file image"));
        dump.push_field("sh_size", format!("{:#x}", self.sh_size), Some("Size in bytes of the section. May be 0"));
        dump.push_field("sh_link", format!("{:#x}", self.sh_link), Some("Contains the section index of an associated section. This field is used for several purposes, depending on the type of section"));
        dump.push_field("sh_info", format!("{:#x}", self.sh_info), Some("Contains extra information about the section. This field is used for several purposes, depending on the type of section"));
        dump.push_field("sh_addralign", format!("{:#x}", self.sh_addralign), Some("Contains the required alignment of the section. This field must be a power of two"));
        dump.push_field("sh_entsize", format!("{:#x}", self.sh_entsize), Some("Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero."));

        return dump;
    }
}

#[derive(Clone, Debug)]
pub enum ELFSectionHeader {
    ELFSectionHeader32(ELFSectionHeader32),
    ELFSectionHeader64(ELFSectionHeader64),
}

impl ELFSectionHeader {
    pub fn name_offset(&self) -> u64 {
        match &self {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_name as u64,
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_name as u64,
        }
    }

    pub fn flags(&self) -> u64 {
        match &self {
            ELFSectionHeader::ELFSectionHeader32(h) => (h.sh_flags as u64),
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_flags,
        }
    }

    pub fn section_type(&self) -> SectionType {
        match &self {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_type.into(),
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_type.into(),
        }
    }

    pub fn virtual_address(&self) -> u64 {
        match &self {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_addr as u64,
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_addr,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ELFSection {
    /// Name parsed from the .shstrtab section
    pub name: String,

    pub header: ELFSectionHeader,
    pub data: Vec<u8>,
}

impl ELFSection {
    pub fn new(header: ELFSectionHeader) -> Self {
        return Self { name: String::new(), header, data: Vec::new() };
    }

    pub fn offset(&self) -> u64 {
        match &self.header {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_offset as u64,
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_offset,
        }
    }

    pub fn size(&self) -> u64 {
        match &self.header {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_size as u64,
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_size,
        }
    }

    #[rustfmt::skip]
    pub fn contains_code(&self) -> bool {
        return (self.header.flags() & SectionFlags::ExecInstr as u64 != 0) &&
               (self.header.section_type() == SectionType::Progbits);
    }

    pub fn dump(&self, elf: &ELF, data: bool, disasm_code: bool) -> Dump {
        let mut dump = Dump::new_from_string(format!("Section ({})", self.name));

        match &self.header {
            ELFSectionHeader::ELFSectionHeader32(h) => dump.push_child(h.dump()),
            ELFSectionHeader::ELFSectionHeader64(h) => dump.push_child(h.dump()),
        }

        if disasm_code {
            if self.contains_code() {

                let res = disasm_elf_code(elf, &self.data, self.header.virtual_address());

                if let Ok(code) = res {
                    dump.set_raw_data(DumpRawData::Code(code));
                } else if data {
                    dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
                }
            } else if data {
                dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
            }
        } else if data {
            dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
        }

        return dump;
    }
}

/* Headers */

#[derive(Clone, Debug, Default)]
pub struct ELFHeaders {
    pub elf_header: ELFHeader,
    pub program_headers: Vec<ELFProgramHeader>,
}

/* ELF */

#[derive(Clone, Debug, Default)]
pub struct ELF {
    pub headers: ELFHeaders,
    pub sections: HashMap<String, ELFSection>,
}

impl ELF {
    fn parse_headers_and_sections(
        &mut self,
        reader: &mut Reader
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.headers.elf_header = ELFHeader::from_parser(reader)?;

        let ph_off = self.headers.elf_header.program_headers_offset();
        let ph_num_entries = self.headers.elf_header.program_headers_num_entries();

        reader.set_position(ph_off as usize)?;

        for _ in 0..ph_num_entries {
            match self.class() {
                ELFClass::ELF32 => self.headers.program_headers
                    .push(ELFProgramHeader::ELFProgramHeader32(ELFProgramHeader32::from_reader(reader)?)),
                ELFClass::ELF64 => self.headers.program_headers
                    .push(ELFProgramHeader::ELFProgramHeader64(ELFProgramHeader64::from_reader(reader)?)),
            }
        }

        let sh_off = self.headers.elf_header.section_headers_offset();
        let sh_num_entries = self.headers.elf_header.section_headers_num_entries();

        reader.set_position(sh_off as usize)?;

        let mut sections = Vec::new();

        for _ in 0..sh_num_entries {
            let mut section = match self.class() {
                ELFClass::ELF32 =>
                    ELFSection::new(ELFSectionHeader::ELFSectionHeader32(ELFSectionHeader32::from_reader(reader)?)),
                ELFClass::ELF64 =>
                    ELFSection::new(ELFSectionHeader::ELFSectionHeader64(ELFSectionHeader64::from_reader(reader)?)),
            };

            let old_position = reader.position();

            reader.set_position(section.offset() as usize)?;

            section.data = reader.read_bytes(section.size() as usize)?.to_vec();

            sections.push(section);

            reader.set_position(old_position)?;
        }

        let shstrtab_sh = &sections[self.get_elf_header().shstr_index()].clone();

        for section in sections.iter_mut() {
            let name_offset = section.header.name_offset() as usize;
            let name = &shstrtab_sh.data[name_offset..];
            let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            section.name = String::from_utf8_lossy(&name[..nul]).to_string();
        }

        self.sections = sections.into_iter().map(|s| (s.name.clone(), s)).collect();

        return Ok(());
    }
}

impl ELF {
    pub fn get_elf_header(&self) -> &ELFHeader {
        return &self.headers.elf_header;
    }

    pub fn class(&self) -> ELFClass {
        match self.headers.elf_header {
            ELFHeader::ELFHeader32(_) => ELFClass::ELF32,
            ELFHeader::ELFHeader64(_) => ELFClass::ELF64,
        }
    }
}

pub fn parse_elf(file_path: &PathBuf) -> Result<ELF, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open and read file");

    let magic_bytes = &file_bytes[0..4];

    if magic_bytes != ELF_MAGIC_ARRAY {
        return Err("File magic number does not match ELF magic number".into());
    }

    let e_data = file_bytes[5];

    let mut reader = match e_data {
        1 => Reader::LittleEndian(LEReader::new(&file_bytes)),
        2 => Reader::BigEndian(BEReader::new(&file_bytes)),
        _ => { return Err("Unknown value for endianness".into()); }
    };

    let mut elf = ELF::default();

    elf.parse_headers_and_sections(&mut reader)?;

    return Ok(elf);
}
