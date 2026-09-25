use crate::{demangle::demangle, disasm::{Architecture, disasm_and_format_code}, dump::{Dump, DumpRawData}, reader::{BEReader, LEReader, Reader}};

use strum::IntoEnumIterator;
use strum_macros::{EnumIter, FromRepr, IntoStaticStr};

use std::{collections::{HashMap, HashSet}, fmt::Display, path::PathBuf};

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
#[derive(Clone, Debug, FromRepr)]
pub enum ELFEndianness {
    Little = 0x1,
    Big = 0x2,
}

/*
 * ELF OS ABI (e_ident[EI_OSABI] in elf header)
 */

#[repr(u8)]
#[derive(Clone, Debug, FromRepr)]
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

impl ELFOsAbi {
    pub fn name(value: u8) -> String {
        return ELFOsAbi::from_repr(value).map_or("Unknown".to_string(), |abi| format!("{:?}", abi));
    }
}

/*
 * Target ISA (e_machine in elf header)
 */

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
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

impl ELFTargetISA {
    pub fn name(value: u16) -> String {
        return ELFTargetISA::from_repr(value).map_or("Unknown".to_string(), |isa| format!("{:?}", isa));
    }
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
        dump.push_field("ei_class", format!("{:#x} ({})", self.ei_class, ELFClass::try_from(self.ei_class).map_or("Unknown".to_string(), |c| format!("{:?}", c))), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x} ({})", self.ei_data, ELFEndianness::from_repr(self.ei_data).map_or("Unknown".to_string(), |e| format!("{:?}", e))), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x} ({})", self.ei_osabi, ELFOsAbi::name(self.ei_osabi)), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{:#x} ({})", self.e_type, ELFFileType::from(self.e_type)), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x} ({})", self.e_machine, ELFTargetISA::name(self.e_machine)), Some("Specifies target instruction set architecture."));
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
        dump.push_field("ei_class", format!("{:#x} ({})", self.ei_class, ELFClass::try_from(self.ei_class).map_or("Unknown".to_string(), |c| format!("{:?}", c))), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x} ({})", self.ei_data, ELFEndianness::from_repr(self.ei_data).map_or("Unknown".to_string(), |e| format!("{:?}", e))), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x} ({})", self.ei_osabi, ELFOsAbi::name(self.ei_osabi)), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{:#x} ({})", self.e_type, ELFFileType::from(self.e_type)), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x} ({})", self.e_machine, ELFTargetISA::name(self.e_machine)), Some("Specifies target instruction set architecture."));
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

    pub fn machine(&self) -> u16 {
        match self {
            Self::ELFHeader32(h) => h.e_machine,
            Self::ELFHeader64(h) => h.e_machine,
        }
    }

    pub fn entry(&self) -> u64 {
        match self {
            Self::ELFHeader32(h) => h.e_entry as u64,
            Self::ELFHeader64(h) => h.e_entry,
        }
    }

    pub fn file_type(&self) -> ELFFileType {
        match self {
            Self::ELFHeader32(h) => h.e_type.into(),
            Self::ELFHeader64(h) => h.e_type.into(),
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
    pub fn program_type(&self) -> ProgramHeaderType {
        match self {
            Self::ELFProgramHeader32(h) => h.p_type.into(),
            Self::ELFProgramHeader64(h) => h.p_type.into(),
        }
    }

    pub fn offset(&self) -> u64 {
        match self {
            Self::ELFProgramHeader32(h) => h.p_offset as u64,
            Self::ELFProgramHeader64(h) => h.p_offset,
        }
    }

    pub fn file_size(&self) -> u64 {
        match self {
            Self::ELFProgramHeader32(h) => h.p_filesz as u64,
            Self::ELFProgramHeader64(h) => h.p_filesz,
        }
    }

    pub fn virtual_address(&self) -> u64 {
        match self {
            Self::ELFProgramHeader32(h) => h.p_vaddr as u64,
            Self::ELFProgramHeader64(h) => h.p_vaddr,
        }
    }

    pub fn memory_size(&self) -> u64 {
        match self {
            Self::ELFProgramHeader32(h) => h.p_memsz as u64,
            Self::ELFProgramHeader64(h) => h.p_memsz,
        }
    }

    pub fn flags(&self) -> u32 {
        match self {
            Self::ELFProgramHeader32(h) => h.p_flags,
            Self::ELFProgramHeader64(h) => h.p_flags,
        }
    }

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
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_flags as u64,
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

    pub fn link(&self) -> usize {
        match &self {
            ELFSectionHeader::ELFSectionHeader32(h) => h.sh_link as usize,
            ELFSectionHeader::ELFSectionHeader64(h) => h.sh_link as usize,
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
                let res = disasm_and_format_code(elf.architecture(), &self.data, self.header.virtual_address());

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

/*
 * Symbols (.symtab, .dynsym)
 */

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum SymbolType {
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    Common = 5,
    Tls = 6,
    GnuIFunc = 10,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum SymbolBinding {
    Local = 0,
    Global = 1,
    Weak = 2,
    GnuUnique = 10,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
pub enum SymbolVisibility {
    Default = 0,
    Internal = 1,
    Hidden = 2,
    Protected = 3,
}

pub const SHN_UNDEF: u16 = 0x0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

#[derive(Clone, Debug, Default)]
pub struct ELFSymbol {
    pub name: String,
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl ELFSymbol {
    pub fn from_reader(reader: &mut Reader, class: &ELFClass) -> Result<Self, Box<dyn std::error::Error>> {
        let mut symbol = Self::default();

        match class {
            ELFClass::ELF32 => {
                symbol.st_name = reader.read_u32()?;
                symbol.st_value = reader.read_u32()? as u64;
                symbol.st_size = reader.read_u32()? as u64;
                symbol.st_info = reader.read_u8()?;
                symbol.st_other = reader.read_u8()?;
                symbol.st_shndx = reader.read_u16()?;
            }
            ELFClass::ELF64 => {
                symbol.st_name = reader.read_u32()?;
                symbol.st_info = reader.read_u8()?;
                symbol.st_other = reader.read_u8()?;
                symbol.st_shndx = reader.read_u16()?;
                symbol.st_value = reader.read_u64()?;
                symbol.st_size = reader.read_u64()?;
            }
        }

        return Ok(symbol);
    }

    pub fn symbol_type(&self) -> Option<SymbolType> {
        return SymbolType::from_repr(self.st_info & 0xf);
    }

    pub fn binding(&self) -> Option<SymbolBinding> {
        return SymbolBinding::from_repr(self.st_info >> 4);
    }

    pub fn visibility(&self) -> Option<SymbolVisibility> {
        return SymbolVisibility::from_repr(self.st_other & 0x3);
    }

    pub fn is_import(&self) -> bool {
        return self.st_shndx == SHN_UNDEF && !self.name.is_empty();
    }

    pub fn demangled_name(&self) -> String {
        return demangle(&self.name).unwrap_or(self.name.clone());
    }

    pub fn section_index_as_string(&self) -> String {
        match self.st_shndx {
            SHN_UNDEF => "UND".to_string(),
            SHN_ABS => "ABS".to_string(),
            SHN_COMMON => "COM".to_string(),
            index => format!("{}", index),
        }
    }

    pub fn as_string(&self) -> String {
        return format!(
            "{:#018x} {:>8} {:<8} {:<8} {:<9} {:>4} {}",
            self.st_value,
            self.st_size,
            self.symbol_type().map_or("Unknown".to_string(), |t| format!("{:?}", t)),
            self.binding().map_or("Unknown".to_string(), |b| format!("{:?}", b)),
            self.visibility().map_or("Unknown".to_string(), |v| format!("{:?}", v)),
            self.section_index_as_string(),
            self.demangled_name(),
        );
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFSymbolTable {
    pub section_name: String,
    pub symbols: Vec<ELFSymbol>,
}

impl ELFSymbolTable {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Symbol Table {} ({} entries)", self.section_name, self.symbols.len()));

        dump.push_field("", format!("{:<18} {:>8} {:<8} {:<8} {:<9} {:>4} {}", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"), None);

        for symbol in self.symbols.iter() {
            dump.push_field("", symbol.as_string(), None);
        }

        return dump;
    }
}

/*
 * Dynamic Section (.dynamic)
 */

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DynamicTag {
    DtNull = 0,
    DtNeeded = 1,
    DtPltrelsz = 2,
    DtPltgot = 3,
    DtHash = 4,
    DtStrtab = 5,
    DtSymtab = 6,
    DtRela = 7,
    DtRelasz = 8,
    DtRelaent = 9,
    DtStrsz = 10,
    DtSyment = 11,
    DtInit = 12,
    DtFini = 13,
    DtSoname = 14,
    DtRpath = 15,
    DtSymbolic = 16,
    DtRel = 17,
    DtRelsz = 18,
    DtRelent = 19,
    DtPltrel = 20,
    DtDebug = 21,
    DtTextrel = 22,
    DtJmprel = 23,
    DtBindNow = 24,
    DtInitArray = 25,
    DtFiniArray = 26,
    DtInitArraysz = 27,
    DtFiniArraysz = 28,
    DtRunpath = 29,
    DtFlags = 30,
    DtPreinitArray = 32,
    DtPreinitArraysz = 33,
    DtSymtabShndx = 34,
    DtRelrsz = 35,
    DtRelr = 36,
    DtRelrent = 37,
    DtGnuHash = 0x6ffffef5,
    DtVersym = 0x6ffffff0,
    DtRelacount = 0x6ffffff9,
    DtRelcount = 0x6ffffffa,
    DtFlags1 = 0x6ffffffb,
    DtVerdef = 0x6ffffffc,
    DtVerdefnum = 0x6ffffffd,
    DtVerneed = 0x6ffffffe,
    DtVerneednum = 0x6fffffff,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DynamicFlag {
    DfOrigin = 0x1,
    DfSymbolic = 0x2,
    DfTextrel = 0x4,
    DfBindNow = 0x8,
    DfStaticTls = 0x10,
}

impl DynamicFlag {
    pub fn flags_as_string(flags: u64) -> String {
        let str_flags: Vec<&'static str> = DynamicFlag::iter()
            .filter(|&flag| (flag as u64 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return str_flags.join(" | ");
    }
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DynamicFlag1 {
    DfNow = 0x1,
    DfGlobal = 0x2,
    DfGroup = 0x4,
    DfNodelete = 0x8,
    DfLoadfltr = 0x10,
    DfInitfirst = 0x20,
    DfNoopen = 0x40,
    DfOrigin = 0x80,
    DfDirect = 0x100,
    DfInterpose = 0x400,
    DfNodeflib = 0x800,
    DfNodump = 0x1000,
    DfPie = 0x8000000,
}

impl DynamicFlag1 {
    pub fn flags_as_string(flags: u64) -> String {
        let str_flags: Vec<&'static str> = DynamicFlag1::iter()
            .filter(|&flag| (flag as u64 & flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return str_flags.join(" | ");
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFDynamicEntry {
    pub d_tag: u64,
    pub d_val: u64,
    pub string: Option<String>,
}

impl ELFDynamicEntry {
    pub fn from_reader(reader: &mut Reader, class: &ELFClass) -> Result<Self, Box<dyn std::error::Error>> {
        let mut entry = Self::default();

        match class {
            ELFClass::ELF32 => {
                entry.d_tag = reader.read_u32()? as u64;
                entry.d_val = reader.read_u32()? as u64;
            }
            ELFClass::ELF64 => {
                entry.d_tag = reader.read_u64()?;
                entry.d_val = reader.read_u64()?;
            }
        }

        return Ok(entry);
    }

    pub fn tag(&self) -> Option<DynamicTag> {
        return DynamicTag::from_repr(self.d_tag);
    }

    pub fn has_string_value(&self) -> bool {
        return matches!(self.tag(), Some(DynamicTag::DtNeeded | DynamicTag::DtSoname | DynamicTag::DtRpath | DynamicTag::DtRunpath));
    }

    pub fn value_as_string(&self) -> String {
        match (self.tag(), &self.string) {
            (_, Some(s)) => format!("{:#x} ({})", self.d_val, s),
            (Some(DynamicTag::DtFlags), _) => format!("{:#x} ({})", self.d_val, DynamicFlag::flags_as_string(self.d_val)),
            (Some(DynamicTag::DtFlags1), _) => format!("{:#x} ({})", self.d_val, DynamicFlag1::flags_as_string(self.d_val)),
            _ => format!("{:#x}", self.d_val),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFDynamic {
    pub entries: Vec<ELFDynamicEntry>,
}

impl ELFDynamic {
    pub fn needed_libraries(&self) -> Vec<&str> {
        return self.entries
            .iter()
            .filter(|e| e.tag() == Some(DynamicTag::DtNeeded))
            .filter_map(|e| e.string.as_deref())
            .collect();
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Dynamic Section ({} entries)", self.entries.len()));

        for entry in self.entries.iter() {
            let tag: &'static str = entry.tag().map_or("UNKNOWN", |t| t.into());
            dump.push_field(tag, entry.value_as_string(), None);
        }

        return dump;
    }
}

/*
 * Relocations (.rel.*, .rela.*)
 */

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum X86_64RelocationType {
    None = 0,
    #[strum(serialize = "64")]
    Direct64 = 1,
    Pc32 = 2,
    Got32 = 3,
    Plt32 = 4,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
    Gotpcrel = 9,
    #[strum(serialize = "32")]
    Direct32 = 10,
    #[strum(serialize = "32S")]
    Direct32S = 11,
    Dtpmod64 = 16,
    Dtpoff64 = 17,
    Tpoff64 = 18,
    Tlsgd = 19,
    Tlsld = 20,
    Gottpoff = 22,
    Tpoff32 = 23,
    Pc64 = 24,
    Irelative = 37,
    Gotpcrelx = 41,
    RexGotpcrelx = 42,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum Aarch64RelocationType {
    None = 0,
    Abs64 = 257,
    Abs32 = 258,
    Abs16 = 259,
    Prel64 = 260,
    Prel32 = 261,
    Prel16 = 262,
    AdrPrelPgHi21 = 275,
    AddAbsLo12Nc = 277,
    Ldst8AbsLo12Nc = 278,
    Jump26 = 282,
    Call26 = 283,
    Ldst16AbsLo12Nc = 284,
    Ldst32AbsLo12Nc = 285,
    Ldst64AbsLo12Nc = 286,
    Ldst128AbsLo12Nc = 299,
    AdrGotPage = 311,
    Ld64GotLo12Nc = 312,
    Copy = 1024,
    GlobDat = 1025,
    JumpSlot = 1026,
    Relative = 1027,
    TlsDtpmod = 1028,
    TlsDtprel = 1029,
    TlsTprel = 1030,
    Tlsdesc = 1031,
    Irelative = 1032,
}

pub fn relocation_type_name(machine: u16, r_type: u32) -> String {
    let name: Option<&'static str> = match ELFTargetISA::from_repr(machine) {
        Some(ELFTargetISA::AMDX86_64) => X86_64RelocationType::from_repr(r_type).map(|t| t.into()),
        Some(ELFTargetISA::Arm64bits) => Aarch64RelocationType::from_repr(r_type).map(|t| t.into()),
        _ => None,
    };

    let prefix = match ELFTargetISA::from_repr(machine) {
        Some(ELFTargetISA::AMDX86_64) => "R_X86_64_",
        Some(ELFTargetISA::Arm64bits) => "R_AARCH64_",
        _ => "",
    };

    return name.map_or(format!("{:#x}", r_type), |n| format!("{}{}", prefix, n));
}

#[derive(Clone, Debug, Default)]
pub struct ELFRelocation {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: Option<i64>,
    pub symbol_name: String,
}

impl ELFRelocation {
    pub fn from_reader(reader: &mut Reader, class: &ELFClass, with_addend: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut reloc = Self::default();

        match class {
            ELFClass::ELF32 => {
                reloc.r_offset = reader.read_u32()? as u64;
                reloc.r_info = reader.read_u32()? as u64;
                reloc.r_addend = if with_addend { Some(reader.read_i32()? as i64) } else { None };
            }
            ELFClass::ELF64 => {
                reloc.r_offset = reader.read_u64()?;
                reloc.r_info = reader.read_u64()?;
                reloc.r_addend = if with_addend { Some(reader.read_i64()?) } else { None };
            }
        }

        return Ok(reloc);
    }

    pub fn symbol_index(&self, class: &ELFClass) -> usize {
        match class {
            ELFClass::ELF32 => (self.r_info >> 8) as usize,
            ELFClass::ELF64 => (self.r_info >> 32) as usize,
        }
    }

    pub fn relocation_type(&self, class: &ELFClass) -> u32 {
        match class {
            ELFClass::ELF32 => (self.r_info & 0xff) as u32,
            ELFClass::ELF64 => (self.r_info & 0xffffffff) as u32,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFRelocationTable {
    pub section_name: String,
    pub class: ELFClass,
    pub machine: u16,
    pub relocations: Vec<ELFRelocation>,
}

impl ELFRelocationTable {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Relocation Table {} ({} entries)", self.section_name, self.relocations.len()));

        dump.push_field("", format!("{:<18} {:<28} {}", "Offset", "Type", "Symbol + Addend"), None);

        for reloc in self.relocations.iter() {
            let addend = match reloc.r_addend {
                Some(a) if a < 0 => format!(" - {:#x}", -a),
                Some(a) => format!(" + {:#x}", a),
                None => String::new(),
            };

            dump.push_field("", format!(
                "{:#018x} {:<28} {}{}",
                reloc.r_offset,
                relocation_type_name(self.machine, reloc.relocation_type(&self.class)),
                demangle(&reloc.symbol_name).unwrap_or(reloc.symbol_name.clone()),
                addend,
            ), None);
        }

        return dump;
    }
}

/*
 * Notes (.note.*)
 */

pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;

#[derive(Clone, Debug, Default)]
pub struct ELFNote {
    pub section_name: String,
    pub name: String,
    pub note_type: u32,
    pub desc: Vec<u8>,
}

impl ELFNote {
    pub fn from_reader(reader: &mut Reader) -> Result<Self, Box<dyn std::error::Error>> {
        let mut note = Self::default();

        let namesz = reader.read_u32()? as usize;
        let descsz = reader.read_u32()? as usize;
        note.note_type = reader.read_u32()?;

        let name = reader.read_bytes(namesz)?;
        let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        note.name = String::from_utf8_lossy(&name[..nul]).to_string();
        reader.set_position(reader.position() + (namesz.next_multiple_of(4) - namesz))?;

        note.desc = reader.read_bytes(descsz)?.to_vec();
        reader.set_position(reader.position() + (descsz.next_multiple_of(4) - descsz))?;

        return Ok(note);
    }

    fn desc_word(&self, index: usize) -> u32 {
        let bytes: [u8; 4] = self.desc[index * 4..index * 4 + 4].try_into().unwrap_or([0; 4]);
        return u32::from_le_bytes(bytes);
    }

    pub fn description(&self) -> String {
        match (self.name.as_str(), self.note_type) {
            ("GNU", NT_GNU_BUILD_ID) => format!("Build ID: {}", self.desc.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
            ("GNU", NT_GNU_ABI_TAG) if self.desc.len() >= 16 => {
                let os = match self.desc_word(0) {
                    0 => "Linux",
                    1 => "GNU",
                    2 => "Solaris",
                    3 => "FreeBSD",
                    _ => "Unknown",
                };

                format!("ABI Tag: {} {}.{}.{}", os, self.desc_word(1), self.desc_word(2), self.desc_word(3))
            }
            ("GNU", NT_GNU_PROPERTY_TYPE_0) => format!("GNU Property: {:02x?}", self.desc),
            _ => format!("{:02x?}", self.desc),
        }
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Note ({})", self.section_name));

        dump.push_field("Owner", self.name.clone(), None);
        dump.push_field("Type", format!("{:#x}", self.note_type), None);
        dump.push_field("Size", format!("{:#x}", self.desc.len()), None);
        dump.push_field("Description", self.description(), None);

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

fn read_c_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }

    let bytes = &data[offset..];
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    return String::from_utf8_lossy(&bytes[..nul]).to_string();
}

#[derive(Clone, Debug, Default)]
pub struct ELF {
    pub headers: ELFHeaders,
    pub sections: HashMap<String, ELFSection>,
    pub interpreter: Option<String>,
    pub symbol_tables: Vec<ELFSymbolTable>,
    pub dynamic: Option<ELFDynamic>,
    pub relocation_tables: Vec<ELFRelocationTable>,
    pub notes: Vec<ELFNote>,
    /// Raw file bytes, only kept when the file has no section headers (loadable segments are read from it)
    pub raw: Vec<u8>,
}

impl ELF {
    fn parse_headers_and_sections(
        &mut self,
        reader: &mut Reader
    ) -> Result<Vec<ELFSection>, Box<dyn std::error::Error>> {
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

            if section.header.section_type() != SectionType::Nobits {
                let old_position = reader.position();

                reader.set_position(section.offset() as usize)?;

                section.data = reader.read_bytes(section.size() as usize)?.to_vec();

                reader.set_position(old_position)?;
            }

            sections.push(section);
        }

        if let Some(shstrtab) = sections.get(self.get_elf_header().shstr_index()).cloned() {
            for section in sections.iter_mut() {
                section.name = read_c_string(&shstrtab.data, section.header.name_offset() as usize);
            }
        }

        return Ok(sections);
    }

    fn parse_interpreter(&mut self, reader: &mut Reader) -> Result<(), Box<dyn std::error::Error>> {
        let interp = self.headers.program_headers
            .iter()
            .find(|ph| ph.program_type() == ProgramHeaderType::Interp);

        if let Some(ph) = interp {
            reader.set_position(ph.offset() as usize)?;
            self.interpreter = Some(read_c_string(reader.read_bytes(ph.file_size() as usize)?, 0));
        }

        return Ok(());
    }

    fn parse_symbols(&self, sections: &[ELFSection], section: &ELFSection) -> Result<Vec<ELFSymbol>, Box<dyn std::error::Error>> {
        let strtab = sections.get(section.header.link()).map_or(&[] as &[u8], |s| s.data.as_slice());
        let mut reader = self.reader_for(&section.data);
        let mut symbols = Vec::new();

        while reader.remaining() > 0 {
            let mut symbol = ELFSymbol::from_reader(&mut reader, &self.class())?;
            symbol.name = read_c_string(strtab, symbol.st_name as usize);
            symbols.push(symbol);
        }

        return Ok(symbols);
    }

    fn parse_symbol_tables(&mut self, sections: &[ELFSection]) -> Result<(), Box<dyn std::error::Error>> {
        for section in sections.iter() {
            if matches!(section.header.section_type(), SectionType::Symtab | SectionType::Dynsym) {
                self.symbol_tables.push(ELFSymbolTable {
                    section_name: section.name.clone(),
                    symbols: self.parse_symbols(sections, section)?,
                });
            }
        }

        return Ok(());
    }

    fn parse_dynamic(&mut self, sections: &[ELFSection]) -> Result<(), Box<dyn std::error::Error>> {
        let Some(section) = sections.iter().find(|s| s.header.section_type() == SectionType::Dynamic) else {
            return Ok(());
        };

        let dynstr = sections.get(section.header.link()).map_or(&[] as &[u8], |s| s.data.as_slice());
        let mut reader = self.reader_for(&section.data);
        let mut dynamic = ELFDynamic::default();

        while reader.remaining() > 0 {
            let mut entry = ELFDynamicEntry::from_reader(&mut reader, &self.class())?;

            if entry.tag() == Some(DynamicTag::DtNull) {
                break;
            }

            if entry.has_string_value() {
                entry.string = Some(read_c_string(dynstr, entry.d_val as usize));
            }

            dynamic.entries.push(entry);
        }

        self.dynamic = Some(dynamic);

        return Ok(());
    }

    fn parse_relocation_tables(&mut self, sections: &[ELFSection]) -> Result<(), Box<dyn std::error::Error>> {
        for section in sections.iter() {
            let with_addend = match section.header.section_type() {
                SectionType::Rela => true,
                SectionType::Rel => false,
                _ => continue,
            };

            let symbols = match sections.get(section.header.link()) {
                Some(symtab) if section.header.link() != 0 => self.parse_symbols(sections, symtab)?,
                _ => Vec::new(),
            };

            let mut reader = self.reader_for(&section.data);
            let mut table = ELFRelocationTable {
                section_name: section.name.clone(),
                class: self.class(),
                machine: self.get_elf_header().machine(),
                relocations: Vec::new(),
            };

            while reader.remaining() > 0 {
                let mut reloc = ELFRelocation::from_reader(&mut reader, &self.class(), with_addend)?;

                if let Some(symbol) = symbols.get(reloc.symbol_index(&self.class())) {
                    reloc.symbol_name = symbol.name.clone();
                }

                table.relocations.push(reloc);
            }

            self.relocation_tables.push(table);
        }

        return Ok(());
    }

    fn parse_notes(&mut self, sections: &[ELFSection]) -> Result<(), Box<dyn std::error::Error>> {
        for section in sections.iter().filter(|s| s.header.section_type() == SectionType::Note) {
            let mut reader = self.reader_for(&section.data);

            while reader.remaining() >= 12 {
                let mut note = ELFNote::from_reader(&mut reader)?;
                note.section_name = section.name.clone();
                self.notes.push(note);
            }
        }

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

    pub fn is_big_endian(&self) -> bool {
        match &self.headers.elf_header {
            ELFHeader::ELFHeader32(h) => h.ei_data == ELFEndianness::Big as u8,
            ELFHeader::ELFHeader64(h) => h.ei_data == ELFEndianness::Big as u8,
        }
    }

    pub fn architecture(&self) -> Architecture {
        match ELFTargetISA::from_repr(self.get_elf_header().machine()) {
            Some(ELFTargetISA::X86) => Architecture::X86,
            Some(ELFTargetISA::AMDX86_64) => Architecture::X86_64,
            Some(ELFTargetISA::Arm64bits) => Architecture::Aarch64,
            _ => Architecture::Unsupported,
        }
    }

    fn reader_for<'a>(&self, data: &'a [u8]) -> Reader<'a> {
        if self.is_big_endian() {
            return Reader::new_be(data);
        }

        return Reader::new_le(data);
    }

    pub fn symbol_table(&self, section_name: &str) -> Option<&ELFSymbolTable> {
        return self.symbol_tables.iter().find(|t| t.section_name == section_name);
    }

    pub fn imported_symbols(&self) -> Vec<&ELFSymbol> {
        return self.symbol_table(".dynsym")
            .map_or(Vec::new(), |t| t.symbols.iter().filter(|s| s.is_import()).collect());
    }

    pub fn dump_program_headers(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Program Headers ({})", self.headers.program_headers.len()));

        if let Some(interpreter) = &self.interpreter {
            dump.push_field("Interpreter", interpreter.clone(), Some("Program interpreter (PT_INTERP)"));
        }

        for header in self.headers.program_headers.iter() {
            dump.push_child(header.dump());
        }

        return dump;
    }

    pub fn dump_imports(&self) -> Dump {
        let mut dump = Dump::new("Imports");

        if let Some(dynamic) = &self.dynamic {
            for library in dynamic.needed_libraries() {
                dump.push_field("Library", library.to_string(), None);
            }
        }

        let imports: HashSet<&str> = self.imported_symbols().iter().map(|s| s.name.as_str()).collect();

        for table in self.relocation_tables.iter() {
            for reloc in table.relocations.iter().filter(|r| imports.contains(r.symbol_name.as_str())) {
                dump.push_field("", format!(
                    "{:#018x} {:<28} {}",
                    reloc.r_offset,
                    relocation_type_name(table.machine, reloc.relocation_type(&table.class)),
                    demangle(&reloc.symbol_name).unwrap_or(reloc.symbol_name.clone()),
                ), None);
            }
        }

        return dump;
    }

    pub fn dump_notes(&self) -> Dump {
        let mut dump = Dump::new_from_string(format!("Notes ({})", self.notes.len()));

        for note in self.notes.iter() {
            dump.push_child(note.dump());
        }

        return dump;
    }
}

pub fn parse_elf(file_path: &PathBuf) -> Result<ELF, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open and read file");

    if file_bytes.len() < 6 || file_bytes[0..4] != ELF_MAGIC_ARRAY {
        return Err("File magic number does not match ELF magic number".into());
    }

    let e_data = file_bytes[5];

    let mut reader = match e_data {
        1 => Reader::LittleEndian(LEReader::new(&file_bytes)),
        2 => Reader::BigEndian(BEReader::new(&file_bytes)),
        _ => { return Err("Unknown value for endianness".into()); }
    };

    let mut elf = ELF::default();

    let sections = elf.parse_headers_and_sections(&mut reader)?;

    elf.parse_interpreter(&mut reader)?;
    elf.parse_symbol_tables(&sections)?;
    elf.parse_dynamic(&sections)?;
    elf.parse_relocation_tables(&sections)?;
    elf.parse_notes(&sections)?;

    if sections.is_empty() {
        elf.raw = file_bytes.clone();
    }

    elf.sections = sections.into_iter().map(|s| (s.name.clone(), s)).collect();

    return Ok(elf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    }

    #[test]
    fn enum_names() {
        assert_eq!(ELFOsAbi::name(0x03), "Linux");
        assert_eq!(ELFOsAbi::name(0xff), "Unknown");
        assert_eq!(ELFTargetISA::name(0xb7), "Arm64bits");
        assert_eq!(ELFTargetISA::name(0x3e), "AMDX86_64");
        assert_eq!(relocation_type_name(0x3e, 7), "R_X86_64_JUMP_SLOT");
        assert_eq!(relocation_type_name(0x3e, 1), "R_X86_64_64");
        assert_eq!(relocation_type_name(0xb7, 1026), "R_AARCH64_JUMP_SLOT");
        assert_eq!(relocation_type_name(0xb7, 275), "R_AARCH64_ADR_PREL_PG_HI21");
        assert_eq!(relocation_type_name(0x03, 7), "0x7");
    }

    #[test]
    fn read_c_string_bounds() {
        assert_eq!(read_c_string(b"abc\0def\0", 4), "def");
        assert_eq!(read_c_string(b"abc", 0), "abc");
        assert_eq!(read_c_string(b"abc", 10), "");
    }

    #[test]
    fn aarch64_static() {
        let elf = parse_elf(&fixture("elf_aarch64_static")).unwrap();

        assert_eq!(elf.architecture(), Architecture::Aarch64);
        assert!(matches!(elf.class(), ELFClass::ELF64));
        assert!(elf.interpreter.is_none());
        assert!(elf.dynamic.is_none());

        let symtab = elf.symbol_table(".symtab").unwrap();
        let start = symtab.symbols.iter().find(|s| s.name == "_start").unwrap();

        assert_eq!(start.binding(), Some(SymbolBinding::Global));
        assert_eq!(start.st_value, elf.sections[".text"].header.virtual_address());

        let code = disasm_and_format_code(elf.architecture(), &elf.sections[".text"].data, start.st_value).unwrap();

        assert!(code[0].ends_with("mov x0, #1"));
        assert!(code.iter().any(|l| l.ends_with("svc #0")));
    }

    #[test]
    fn aarch64_dynamic() {
        let elf = parse_elf(&fixture("elf_aarch64_dyn")).unwrap();

        assert_eq!(elf.interpreter.as_deref(), Some("/lib/ld-linux-aarch64.so.1"));
        assert_eq!(elf.dynamic.as_ref().unwrap().needed_libraries(), vec!["libfoo.so"]);

        let imports: Vec<&str> = elf.imported_symbols().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(imports, vec!["lib_add"]);

        let reloc = elf.relocation_tables
            .iter()
            .flat_map(|t| t.relocations.iter().map(move |r| (t, r)))
            .find(|(_, r)| r.symbol_name == "lib_add")
            .unwrap();

        assert_eq!(relocation_type_name(reloc.0.machine, reloc.1.relocation_type(&reloc.0.class)), "R_AARCH64_JUMP_SLOT");

        let build_id = elf.notes.iter().find(|n| n.note_type == NT_GNU_BUILD_ID).unwrap();
        assert_eq!(build_id.name, "GNU");
        assert_eq!(build_id.desc.len(), 20);
    }

    #[test]
    fn x86_64_dynamic() {
        let elf = parse_elf(&fixture("elf_x86_64_dyn")).unwrap();

        assert_eq!(elf.architecture(), Architecture::X86_64);
        assert_eq!(elf.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));

        let dynamic = elf.dynamic.as_ref().unwrap();
        assert!(dynamic.entries.iter().any(|e| e.tag() == Some(DynamicTag::DtStrtab)));
        assert!(dynamic.entries.iter().all(|e| e.tag() != Some(DynamicTag::DtNull)));

        let imports = elf.dump_imports();
        let lines: Vec<&str> = imports.iter_fields().map(|f| f.value.as_str()).collect();

        assert!(lines.contains(&"libfoo.so"));
        assert!(lines.iter().any(|l| l.contains("R_X86_64_JUMP_SLOT") && l.ends_with("lib_add")));
    }

    #[test]
    fn nobits_sections_have_no_data() {
        let elf = parse_elf(&fixture("elf_x86_64_dyn")).unwrap();

        for section in elf.sections.values() {
            if section.header.section_type() == SectionType::Nobits {
                assert!(section.data.is_empty());
            }
        }
    }
}
