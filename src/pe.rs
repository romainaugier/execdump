use byteorder::{LittleEndian, ReadBytesExt};
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::{collections::HashMap, io::Read};

use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};

use capstone::prelude::*;

use crate::format::format_u32_as_ctime;
use crate::disasm::is_padding_instruction;
use crate::dump::*;

/*
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */

/*
 * MS-DOS Header present in every PE file
 */

/* Magic number for MS-DOS executable */
pub const DOS_MAGIC: u16 = 0x5a4d;
pub const DOS_MAGIC_ARRAY: [u8; 2] = [b'M', b'Z'];

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct DOSHeader {
    pub e_magic: u16,      // Magic number: 0x5A4D or MZ
    pub e_cblp: u16,       // Bytes on last page of file
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header, in paragraphs
    pub e_minalloc: u16,   // Min - extra paragraphs needed
    pub e_maxalloc: u16,   // Max - extra paragraphs needed
    pub e_ss: u16,         // Initial (relative) SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial (relative) CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved words
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: u32,     // Offset to NT header
}

impl DOSHeader {
    fn new() -> DOSHeader {
        return DOSHeader::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<DOSHeader, Box<dyn Error>> {
        let mut header: DOSHeader = DOSHeader::new();
        header.e_magic = cursor.read_u16::<LittleEndian>()?;

        if header.e_magic != DOS_MAGIC {
            return Err("Invalid DOS magic number".into());
        }

        cursor.set_position(0x3C);

        header.e_lfanew = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("DOS Header");

        dump.push_field("e_magic", format!("{:#x}", self.e_magic), Some("Magic number: 0x5A4D or MZ"));
        dump.push_field("e_cblp", format!("{:#x}", self.e_cblp), Some("Bytes on last page of file"));
        dump.push_field("e_cp", format!("{:#x}", self.e_cp), Some("Pages in file"));
        dump.push_field("e_crlc", format!("{:#x}", self.e_crlc), Some("Relocations"));
        dump.push_field("e_cparhdr", format!("{:#x}", self.e_cparhdr), Some("Size of header, in paragraphs"));
        dump.push_field("e_minalloc", format!("{:#x}", self.e_minalloc), Some("Min - extra paragraphs needed"));
        dump.push_field("e_maxalloc", format!("{:#x}", self.e_maxalloc), Some("Max - extra paragraphs needed"));
        dump.push_field("e_ss", format!("{:#x}", self.e_ss), Some("Initial (relative) CS value"));
        dump.push_field("e_sp", format!("{:#x}", self.e_sp), Some("Initial SP value"));
        dump.push_field("e_csum", format!("{:#x}", self.e_csum), Some("Checksum"));
        dump.push_field("e_ip", format!("{:#x}", self.e_ip), Some("Initial IP value"));
        dump.push_field("e_cs", format!("{:#x}", self.e_cs), Some("Initial (relative)S value"));
        dump.push_field("e_lfarlc", format!("{:#x}", self.e_lfarlc), Some("File address of relocation table"));
        dump.push_field("e_ovno", format!("{:#x}", self.e_ovno), Some("Overlay number"));
        dump.push_field("e_res", format!("{:?}", self.e_res), Some("Reserved words"));
        dump.push_field("e_oemid", format!("{:#x}", self.e_oemid), Some("OEM identifier"));
        dump.push_field("e_oeminfo", format!("{:#x}", self.e_oeminfo), Some("OEM information"));
        dump.push_field("e_res2", format!("{:?}", self.e_res2), Some("Reserved words"));
        dump.push_field("e_lfanew", format!("{:#x}", self.e_lfanew), Some("Offset to NT header"));

        return dump;
    }
}

/*
 * Machine Types (machine field in COFF Header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    Unknown = 0x0, // The content of this field is assumed to be applicable to any machine type
    Alpha = 0x184, // Alpha AXP, 32-bit address space
    Alpha64 = 0x284, // Alpha 64, 64-bit address space
    AM33 = 0x1d3,  // Matsushita AM33
    AMD64 = 0x8664, // x64
    ARM = 0x1c0,   // ARM little endian
    ARM64 = 0xaa64, // ARM64 little endian
    ARM64EC = 0xA641, // ABI that enables interoperability between native ARM64 and emulated x64 code.
    ARM64X = 0xA64E, // Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.
    ARMNT = 0x1c4,   // ARM Thumb-2 little endian
    EBC = 0xebc,     // EFI byte code
    I386 = 0x14c,    // Intel 386 or later processors and compatible processors
    IA64 = 0x200,    // Intel Itanium processor family
    LOONGARCH32 = 0x6232, // LoongArch 32-bit processor family
    LOONGARCH64 = 0x6264, // LoongArch 64-bit processor family
    M32R = 0x9041,   // Mitsubishi M32R little endian
    MIPS16 = 0x266,  // MIPS16
    MIPSFPU = 0x366, // MIPS with FPU
    MIPSFPU16 = 0x466, // MIPS16 with FPU
    POWERPC = 0x1f0, // Power PC little endian
    POWERPCFP = 0x1f1, // Power PC with floating point support
    R3000BE = 0x160, // MIPS I compatible 32-bit big endian
    R3000 = 0x162,   // MIPS I compatible 32-bit little endian
    R4000 = 0x166,   // MIPS III compatible 64-bit little endian
    R10000 = 0x168,  // MIPS IV compatible 64-bit little endian
    RISCV32 = 0x5032, // RISC-V 32-bit address space
    RISCV64 = 0x5064, // RISC-V 64-bit address space
    RISCV128 = 0x5128, // RISC-V 128-bit address space
    SH3 = 0x1a2,     // Hitachi SH3
    SH3DSP = 0x1a3,  // Hitachi SH3 DSP
    SH4 = 0x1a6,     // Hitachi SH4
    SH5 = 0x1a8,     // Hitachi SH5
    THUMB = 0x1c2,   // Thumb
    WCEMIPSV2 = 0x169, // MIPS little-endian WCE v2
}

impl From<u16> for MachineType {
    fn from(value: u16) -> Self {
        match value {
            v if v == MachineType::Unknown as u16 => MachineType::Unknown,
            v if v == MachineType::Alpha as u16 => MachineType::Alpha,
            v if v == MachineType::Alpha64 as u16 => MachineType::Alpha64,
            v if v == MachineType::AM33 as u16 => MachineType::AM33,
            v if v == MachineType::AMD64 as u16 => MachineType::AMD64,
            v if v == MachineType::ARM as u16 => MachineType::ARM,
            v if v == MachineType::ARM64 as u16 => MachineType::ARM64,
            v if v == MachineType::ARM64EC as u16 => MachineType::ARM64EC,
            v if v == MachineType::ARM64X as u16 => MachineType::ARM64X,
            v if v == MachineType::ARMNT as u16 => MachineType::ARMNT,
            v if v == MachineType::EBC as u16 => MachineType::EBC,
            v if v == MachineType::I386 as u16 => MachineType::I386,
            v if v == MachineType::IA64 as u16 => MachineType::IA64,
            v if v == MachineType::LOONGARCH32 as u16 => MachineType::LOONGARCH32,
            v if v == MachineType::LOONGARCH64 as u16 => MachineType::LOONGARCH64,
            v if v == MachineType::M32R as u16 => MachineType::M32R,
            v if v == MachineType::MIPS16 as u16 => MachineType::MIPS16,
            v if v == MachineType::MIPSFPU as u16 => MachineType::MIPSFPU,
            v if v == MachineType::MIPSFPU16 as u16 => MachineType::MIPSFPU16,
            v if v == MachineType::POWERPC as u16 => MachineType::POWERPC,
            v if v == MachineType::POWERPCFP as u16 => MachineType::POWERPCFP,
            v if v == MachineType::R3000BE as u16 => MachineType::R3000BE,
            v if v == MachineType::R3000 as u16 => MachineType::R3000,
            v if v == MachineType::R4000 as u16 => MachineType::R4000,
            v if v == MachineType::R10000 as u16 => MachineType::R10000,
            v if v == MachineType::RISCV32 as u16 => MachineType::RISCV32,
            v if v == MachineType::RISCV64 as u16 => MachineType::RISCV64,
            v if v == MachineType::RISCV128 as u16 => MachineType::RISCV128,
            v if v == MachineType::SH3 as u16 => MachineType::SH3,
            v if v == MachineType::SH3DSP as u16 => MachineType::SH3DSP,
            v if v == MachineType::SH4 as u16 => MachineType::SH4,
            v if v == MachineType::SH5 as u16 => MachineType::SH5,
            v if v == MachineType::THUMB as u16 => MachineType::THUMB,
            v if v == MachineType::WCEMIPSV2 as u16 => MachineType::WCEMIPSV2,
            _ => MachineType::Unknown,
        }
    }
}

/*
 * Characteristics Flags (characteristics field in COFF header)
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CharacteristicsFlag {
    RelocsStripped = 0x0001, // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    ExecutableImage = 0x0002, // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    LineNumsStripped = 0x0004, // COFF line numbers have been removed. This flag is deprecated and should be zero.
    LocalSymsStripped = 0x0008, // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    AggressiveWSTrim = 0x0010, // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    LargeAddressAware = 0x0020, // Application can handle > 2-GB addresses.
    UnusedFlag = 0x0040,       // This flag is reserved for future use.
    BytesReversedLo = 0x0080, // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    Bit32Machine = 0x0100,    // Machine is based on a 32-bit-word architecture.
    DebugStripped = 0x0200,   // Debugging information is removed from the image file.
    RemovableRunFromSwap = 0x0400, // If the image is on removable media, fully load it and copy it to the swap file.
    NetRunFromSwap = 0x0800, // If the image is on network media, fully load it and copy it to the swap file.
    System = 0x1000,         // The image file is a system file, not a user program.
    DLL = 0x2000, // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    UPSystemOnly = 0x4000, // The file should be run only on a uniprocessor machine.
    BytesReversedHi = 0x8000, // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
}

/*
 * COFF Header
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct COFFHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl COFFHeader {
    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<COFFHeader, Box<dyn Error>> {
        let mut header: COFFHeader = COFFHeader::default();

        header.machine = cursor.read_u16::<LittleEndian>()?;
        header.number_of_sections = cursor.read_u16::<LittleEndian>()?;
        header.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_symbol_table = cursor.read_u32::<LittleEndian>()?;
        header.number_of_symbols = cursor.read_u32::<LittleEndian>()?;
        header.size_of_optional_header = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u16::<LittleEndian>()?;

        return Ok(header);
    }

    pub fn characteristics_as_string(&self) -> String {
        let flags: Vec<&'static str> = CharacteristicsFlag::iter()
            .filter(|&flag| (flag as u16 & self.characteristics) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("COFF Header");

        dump.push_field("Machine", format!("{:#x} ({:#?})", self.machine, MachineType::from(self.machine)), None);
        dump.push_field("NumberOfSections", format!("{:#x}", self.number_of_sections), None);
        dump.push_field("TimeDateStamp", format!("{:#x} ({})", self.time_date_stamp, format_u32_as_ctime(self.time_date_stamp)), None);
        dump.push_field("PointerToSymbolTable", format!("{:#x}", self.pointer_to_symbol_table), None);
        dump.push_field("NumberOfSymbols", format!("{:#x}", self.number_of_symbols), None);
        dump.push_field("SizeOfOptionalHeader", format!("{:#x}", self.size_of_optional_header), None);
        dump.push_field("Characteristics", format!("{:#x} ({})", self.characteristics, self.characteristics_as_string()), None);

        return dump;
    }
}

const NT_PE_SIGNATURE: u32 = 0x4550;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct NTHeader {
    pub signature: u32,
    pub coff_header: COFFHeader,
}

impl NTHeader {
    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<NTHeader, Box<dyn Error>> {
        let mut header: NTHeader = NTHeader::default();
        header.signature = cursor.read_u32::<LittleEndian>()?;

        if header.signature != NT_PE_SIGNATURE {
            return Err("Invalid PE signature in NT Header".into());
        }

        header.coff_header = COFFHeader::from_parser(cursor)?;

        return Ok(header);
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("NT Header");

        dump.push_field("Signature", format!("{:#x}", self.signature), None);

        dump.push_child(self.coff_header.dump());

        return dump;
    }
}

/*
 * Image Data Directory (Last 16 members of the Optional Header)
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl ImageDataDirectory {
    pub fn new() -> ImageDataDirectory {
        return ImageDataDirectory::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ImageDataDirectory, Box<dyn std::error::Error>> {
        let mut idd = ImageDataDirectory::new();

        idd.virtual_address = cursor.read_u32::<LittleEndian>()?;
        idd.size = cursor.read_u32::<LittleEndian>()?;

        return Ok(idd);
    }
}

/*
 * Windows Subsystem
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum Subsystem {
    Unknown = 0,                 // An unknown subsystem
    Native = 1,                  // Device drivers and native Windows processes
    WindowsGui = 2,              // The Windows graphical user interface (GUI) subsystem
    WindowsCui = 3,              // The Windows character subsystem
    Os2Cui = 5,                  // The OS/2 character subsystem
    PosixCui = 7,                // The Posix character subsystem
    NativeWindows = 8,           // Native Win9x driver
    WindowsCEGui = 9,            // Windows CE
    EfiApplication = 10,         // An Extensible Firmware Interface (EFI) application
    EfiBootServiceDriver = 11,   // An EFI driver with boot services
    EfiRuntimeDriver = 12,       // An EFI driver with run-time services
    EfiRom = 13,                 // An EFI ROM image
    XBOX = 14,                   // XBOX
    WindowsBootApplication = 16, // Windows boot application.
}

impl From<u16> for Subsystem {
    fn from(value: u16) -> Self {
        match value {
            v if v == Subsystem::Unknown as u16 => Subsystem::Unknown,
            v if v == Subsystem::Native as u16 => Subsystem::Native,
            v if v == Subsystem::WindowsGui as u16 => Subsystem::WindowsGui,
            v if v == Subsystem::WindowsCui as u16 => Subsystem::WindowsCui,
            v if v == Subsystem::Os2Cui as u16 => Subsystem::Os2Cui,
            v if v == Subsystem::PosixCui as u16 => Subsystem::PosixCui,
            v if v == Subsystem::NativeWindows as u16 => Subsystem::NativeWindows,
            v if v == Subsystem::WindowsCEGui as u16 => Subsystem::WindowsCEGui,
            v if v == Subsystem::EfiApplication as u16 => Subsystem::EfiApplication,
            v if v == Subsystem::EfiBootServiceDriver as u16 => Subsystem::EfiBootServiceDriver,
            v if v == Subsystem::EfiRuntimeDriver as u16 => Subsystem::EfiRuntimeDriver,
            v if v == Subsystem::EfiRom as u16 => Subsystem::EfiRom,
            v if v == Subsystem::XBOX as u16 => Subsystem::XBOX,
            v if v == Subsystem::WindowsBootApplication as u16 => Subsystem::WindowsBootApplication,
            _ => Subsystem::Unknown,
        }
    }
}

impl Subsystem {
    pub fn as_static_str(&self) -> &'static str {
        return self.into();
    }
}

/*
 * DLL Characteristics
 */

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DLLCharacteristicsFlags {
    Reserved1 = 0x0001,           // Reserved, must be zero.
    Reserved2 = 0x0002,           // Reserved, must be zero
    Reserved4 = 0x0004,           // Reserved, must be zero.
    Reserved8 = 0x0008,           // Reserved, must be zero.
    HighEntropyVA = 0x0020,       // Image can handle a high entropy 64-bit virtual address space.
    DynamicBase = 0x0040,         // DLL can be relocated at load time.
    ForceIntegrity = 0x0080,      // Code Integrity checks are enforced.
    NXCompat = 0x0100,            // Image is NX compatible.
    NoIsolation = 0x0200,         // Isolation aware, but do not isolate the image.
    NoSeh = 0x0400, // Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NoBind = 0x0800, // Do not bind the image.
    AppContainer = 0x1000, // Image must execute in an AppContainer.
    WdmDriver = 0x2000, // A WDM driver.
    GuardCf = 0x4000, // Image supports Control Flow Guard.
    TerminalServerAware = 0x8000, // Terminal Server
}

impl DLLCharacteristicsFlags {
    pub fn flags_as_string(characteristics: u16) -> String {
        let flags: Vec<&'static str> = DLLCharacteristicsFlags::iter()
            .filter(|&flag| (flag as u16 & characteristics) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }
}

/*
 * Optional Header for 32/32+ images
 */

/* Magic number for 32 bits PE */
const PE_FORMAT_32_MAGIC: u16 = 0x10b;

/* Magic number for 64 bits PE (PE32+ in the doc) */
const PE_FORMAT_64_MAGIC: u16 = 0x20b;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader32 {
    /* Standard Fields */
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,

    /* Windows Specific Fields */
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignement: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32, /* reserved field */
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32, /* reserved_field */
    pub number_of_rva_and_sizes: u32,

    /* Data Directories */
    pub export_table: ImageDataDirectory,
    pub import_table: ImageDataDirectory,
    pub resource_table: ImageDataDirectory,
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    pub base_relocation_table: ImageDataDirectory,
    pub debug: ImageDataDirectory,
    pub architecture: ImageDataDirectory, /* reserved field */
    pub global_ptr: ImageDataDirectory,
    pub tls_table: ImageDataDirectory,
    pub load_config_table: ImageDataDirectory,
    pub bound_import: ImageDataDirectory,
    pub import_address_table: ImageDataDirectory, /* IAT */
    pub delay_import_descriptor: ImageDataDirectory,
    pub clr_runtime_header: ImageDataDirectory,
    pub zero: ImageDataDirectory, /* reserved field */
}

impl OptionalHeader32 {
    fn new() -> OptionalHeader32 {
        return OptionalHeader32::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<OptionalHeader32, Box<dyn Error>> {
        let mut header: OptionalHeader32 = OptionalHeader32::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.base_of_data = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u32::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u32::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Optional Header (32-bits)");

        let mut standard_fields_dump = Dump::new("Standard Fields");

        standard_fields_dump.push_field("Magic", format!("{:#x}", self.magic), None);
        standard_fields_dump.push_field("MajorLinkerVersion", format!("{:#x}", self.major_linker_version), None);
        standard_fields_dump.push_field("MinorLinkerVersion", format!("{:#x}", self.minor_linker_version), None);
        standard_fields_dump.push_field("SizeOfCode", format!("{:#x}", self.size_of_code), None);
        standard_fields_dump.push_field("SizeOfInitializedData", format!("{:#x}", self.size_of_initialized_data), None);
        standard_fields_dump.push_field("SizeOfUninitializedData", format!("{:#x}", self.size_of_uninitialized_data), None);
        standard_fields_dump.push_field("AddressOfEntryPoint", format!("{:#x}", self.address_of_entry_point), None);
        standard_fields_dump.push_field("BaseOfCode", format!("{:#x}", self.base_of_code), None);
        standard_fields_dump.push_field("BaseOfData", format!("{:#x}", self.base_of_data), None);

        dump.push_child(standard_fields_dump);

        let mut windows_specific_dump = Dump::new("Windows Specific Fields");

        windows_specific_dump.push_field("ImageBase", format!("{:#x}", self.image_base), None);
        windows_specific_dump.push_field("SectionAlignment", format!("{:#x}", self.section_alignment), None);
        windows_specific_dump.push_field("FileAlignement", format!("{:#x}", self.file_alignement), None);
        windows_specific_dump.push_field("MajorOperatingSystemVersion", format!("{:#x}", self.major_operating_system_version), None);
        windows_specific_dump.push_field("MinorOperatingSystemVersion", format!("{:#x}", self.minor_operating_system_version), None);
        windows_specific_dump.push_field("MajorImageVersion", format!("{:#x}", self.major_image_version), None);
        windows_specific_dump.push_field("MinorImageVersion", format!("{:#x}", self.minor_image_version), None);
        windows_specific_dump.push_field("MajorSubsystemVersion", format!("{:#x}", self.major_subsystem_version), None);
        windows_specific_dump.push_field("MinorSubsystemVersion", format!("{:#x}", self.minor_subsystem_version), None);
        windows_specific_dump.push_field("Win32VersionValue", format!("{:#x}", self.win32_version_value), None);
        windows_specific_dump.push_field("SizeOfImage", format!("{:#x}", self.size_of_image), None);
        windows_specific_dump.push_field("SizeOfHeaders", format!("{:#x}", self.size_of_headers), None);
        windows_specific_dump.push_field("Checksum", format!("{:#x}", self.checksum), None);
        windows_specific_dump.push_field("Subsystem", format!("{:#x} ({})", self.subsystem, Subsystem::from(self.subsystem).as_static_str()), None);
        windows_specific_dump.push_field("DLLCharacteristics", format!("{:#x} ({})", self.dll_characteristics, DLLCharacteristicsFlags::flags_as_string(self.dll_characteristics)), None);
        windows_specific_dump.push_field("SizeOfStackReserve", format!("{:#x}", self.size_of_stack_reserve), None);
        windows_specific_dump.push_field("SizeOfStackCommit", format!("{:#x}", self.size_of_stack_commit), None);
        windows_specific_dump.push_field("SizeOfHeapReserve", format!("{:#x}", self.size_of_heap_reserve), None);
        windows_specific_dump.push_field("SizeOfHeapCommit", format!("{:#x}", self.size_of_heap_commit), None);
        windows_specific_dump.push_field("LoaderFlags", format!("{:#x}", self.loader_flags), None);
        windows_specific_dump.push_field("NumberOfRvaAndSizes", format!("{:#x}", self.number_of_rva_and_sizes), None);

        dump.push_child(windows_specific_dump);

        let mut data_directories_dump = Dump::new("Data Directories");

        data_directories_dump.push_field("ExportTable", format!("address: {:#x} sz: {:#x}", self.export_table.virtual_address, self.export_table.size), None);
        data_directories_dump.push_field("ImportTable", format!("address: {:#x} sz: {:#x}", self.import_table.virtual_address, self.import_table.size), None);
        data_directories_dump.push_field("ResourceTable", format!("address: {:#x} sz: {:#x}", self.resource_table.virtual_address, self.resource_table.size), None);
        data_directories_dump.push_field("ExceptionTable", format!("address: {:#x} sz: {:#x}", self.exception_table.virtual_address, self.exception_table.size), None);
        data_directories_dump.push_field("CertificateTable", format!("address: {:#x} sz: {:#x}", self.certificate_table.virtual_address, self.certificate_table.size), None);
        data_directories_dump.push_field("BaseRelocationTable", format!("address: {:#x} sz: {:#x}", self.base_relocation_table.virtual_address, self.base_relocation_table.size), None);
        data_directories_dump.push_field("Debug", format!("address: {:#x} sz: {:#x}", self.debug.virtual_address, self.debug.size), None);
        data_directories_dump.push_field("Architecture", format!("address: {:#x} sz: {:#x}", self.architecture.virtual_address, self.architecture.size), None);
        data_directories_dump.push_field("GlobalPtr", format!("address: {:#x} sz: {:#x}", self.global_ptr.virtual_address, self.global_ptr.size), None);
        data_directories_dump.push_field("TLSTable", format!("address: {:#x} sz: {:#x}", self.tls_table.virtual_address, self.tls_table.size), None);
        data_directories_dump.push_field("LoadConfigTable", format!("address: {:#x} sz: {:#x}", self.load_config_table.virtual_address, self.load_config_table.size), None);
        data_directories_dump.push_field("BoundImport", format!("address: {:#x} sz: {:#x}", self.bound_import.virtual_address, self.bound_import.size), None);
        data_directories_dump.push_field("ImportAddressTable", format!("address: {:#x} sz: {:#x}", self.import_address_table.virtual_address, self.import_address_table.size), None);
        data_directories_dump.push_field("DelayImportDescriptor", format!("address: {:#x} sz: {:#x}", self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size), None);
        data_directories_dump.push_field("CLRRuntimeHeader", format!("address: {:#x} sz: {:#x}", self.clr_runtime_header.virtual_address, self.clr_runtime_header.size), None);
        data_directories_dump.push_field("Zero", format!("address: {:#x} sz: {:#x}", self.zero.virtual_address, self.zero.size), None);

        dump.push_child(data_directories_dump);

        return dump;
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader64 {
    /* Standard Fieds */
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,

    /* Windows Specific Fields */
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignement: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32, /* reserved field */
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32, /* reserved_field */
    pub number_of_rva_and_sizes: u32,

    /* Data Directories */
    pub export_table: ImageDataDirectory,
    pub import_table: ImageDataDirectory,
    pub resource_table: ImageDataDirectory,
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    pub base_relocation_table: ImageDataDirectory,
    pub debug: ImageDataDirectory,
    pub architecture: ImageDataDirectory, /* reserved field */
    pub global_ptr: ImageDataDirectory,
    pub tls_table: ImageDataDirectory,
    pub load_config_table: ImageDataDirectory,
    pub bound_import: ImageDataDirectory,
    pub import_address_table: ImageDataDirectory, /* IAT */
    pub delay_import_descriptor: ImageDataDirectory,
    pub clr_runtime_header: ImageDataDirectory,
    pub zero: ImageDataDirectory, /* reserved field */
}

impl OptionalHeader64 {
    fn new() -> OptionalHeader64 {
        return OptionalHeader64::default();
    }

    fn from_parser(cursor: &mut io::Cursor<&Vec<u8>>) -> Result<OptionalHeader64, Box<dyn Error>> {
        let mut header: OptionalHeader64 = OptionalHeader64::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u64::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u64::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Optional Header (64-bits)");

        let mut standard_fields_dump = Dump::new("Standard Fields");

        standard_fields_dump.push_field("Magic", format!("{:#x}", self.magic), None);
        standard_fields_dump.push_field("MajorLinkerVersion", format!("{:#x}", self.major_linker_version), None);
        standard_fields_dump.push_field("MinorLinkerVersion", format!("{:#x}", self.minor_linker_version), None);
        standard_fields_dump.push_field("SizeOfCode", format!("{:#x}", self.size_of_code), None);
        standard_fields_dump.push_field("SizeOfInitializedData", format!("{:#x}", self.size_of_initialized_data), None);
        standard_fields_dump.push_field("SizeOfUninitializedData", format!("{:#x}", self.size_of_uninitialized_data), None);
        standard_fields_dump.push_field("AddressOfEntryPoint", format!("{:#x}", self.address_of_entry_point), None);
        standard_fields_dump.push_field("BaseOfCode", format!("{:#x}", self.base_of_code), None);

        dump.push_child(standard_fields_dump);

        let mut windows_specific_fields_dump = Dump::new("Windows Specific Fields");

        windows_specific_fields_dump.push_field("ImageBase", format!("{:#x}", self.image_base), None);
        windows_specific_fields_dump.push_field("SectionAlignment", format!("{:#x}", self.section_alignment), None);
        windows_specific_fields_dump.push_field("FileAlignement", format!("{:#x}", self.file_alignement), None);
        windows_specific_fields_dump.push_field("MajorOperatingSystemVersion", format!("{:#x}", self.major_operating_system_version), None);
        windows_specific_fields_dump.push_field("MinorOperatingSystemVersion", format!("{:#x}", self.minor_operating_system_version), None);
        windows_specific_fields_dump.push_field("MajorImageVersion", format!("{:#x}", self.major_image_version), None);
        windows_specific_fields_dump.push_field("MinorImageVersion", format!("{:#x}", self.minor_image_version), None);
        windows_specific_fields_dump.push_field("MajorSubsystemVersion", format!("{:#x}", self.major_subsystem_version), None);
        windows_specific_fields_dump.push_field("MinorSubsystemVersion", format!("{:#x}", self.minor_subsystem_version), None);
        windows_specific_fields_dump.push_field("Win32VersionValue", format!("{:#x}", self.win32_version_value), None);
        windows_specific_fields_dump.push_field("SizeOfImage", format!("{:#x}", self.size_of_image), None);
        windows_specific_fields_dump.push_field("SizeOfHeaders", format!("{:#x}", self.size_of_headers), None);
        windows_specific_fields_dump.push_field("Checksum", format!("{:#x}", self.checksum), None);
        windows_specific_fields_dump.push_field("Subsystem", format!("{:#x} ({})", self.subsystem, Subsystem::from(self.subsystem).as_static_str()), None);
        windows_specific_fields_dump.push_field("DLLCharacteristics", format!("{:#x} ({})", self.dll_characteristics, DLLCharacteristicsFlags::flags_as_string(self.dll_characteristics)), None);
        windows_specific_fields_dump.push_field("SizeOfStackReserve", format!("{:#x}", self.size_of_stack_reserve), None);
        windows_specific_fields_dump.push_field("SizeOfStackCommit", format!("{:#x}", self.size_of_stack_commit), None);
        windows_specific_fields_dump.push_field("SizeOfHeapReserve", format!("{:#x}", self.size_of_heap_reserve), None);
        windows_specific_fields_dump.push_field("SizeOfHeapCommit", format!("{:#x}", self.size_of_heap_commit), None);
        windows_specific_fields_dump.push_field("LoaderFlags", format!("{:#x}", self.loader_flags), None);
        windows_specific_fields_dump.push_field("NumberOfRvaAndSizes", format!("{:#x}", self.number_of_rva_and_sizes), None);

        dump.push_child(windows_specific_fields_dump);

        let mut data_directories_dump = Dump::new("Data Directories");

        data_directories_dump.push_field("ExportTable", format!("address: {:#x} sz: {:#x}", self.export_table.virtual_address, self.export_table.size), None);
        data_directories_dump.push_field("ImportTable", format!("address: {:#x} sz: {:#x}", self.import_table.virtual_address, self.import_table.size), None);
        data_directories_dump.push_field("ResourceTable", format!("address: {:#x} sz: {:#x}", self.resource_table.virtual_address, self.resource_table.size), None);
        data_directories_dump.push_field("ExceptionTable", format!("address: {:#x} sz: {:#x}", self.exception_table.virtual_address, self.exception_table.size), None);
        data_directories_dump.push_field("CertificateTable", format!("address: {:#x} sz: {:#x}", self.certificate_table.virtual_address, self.certificate_table.size), None);
        data_directories_dump.push_field("BaseRelocationTable", format!("address: {:#x} sz: {:#x}", self.base_relocation_table.virtual_address, self.base_relocation_table.size), None);
        data_directories_dump.push_field("Debug", format!("address: {:#x} sz: {:#x}", self.debug.virtual_address, self.debug.size), None);
        data_directories_dump.push_field("Architecture", format!("address: {:#x} sz: {:#x}", self.architecture.virtual_address, self.architecture.size), None);
        data_directories_dump.push_field("GlobalPtr", format!("address: {:#x} sz: {:#x}", self.global_ptr.virtual_address, self.global_ptr.size), None);
        data_directories_dump.push_field("TLSTable", format!("address: {:#x} sz: {:#x}", self.tls_table.virtual_address, self.tls_table.size), None);
        data_directories_dump.push_field("LoadConfigTable", format!("address: {:#x} sz: {:#x}", self.load_config_table.virtual_address, self.load_config_table.size), None);
        data_directories_dump.push_field("BoundImport", format!("address: {:#x} sz: {:#x}", self.bound_import.virtual_address, self.bound_import.size), None);
        data_directories_dump.push_field("ImportAddressTable", format!("address: {:#x} sz: {:#x}", self.import_address_table.virtual_address, self.import_address_table.size), None);
        data_directories_dump.push_field("DelayImportDescriptor", format!("address: {:#x} sz: {:#x}", self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size), None);
        data_directories_dump.push_field("CLRRuntimeHeader", format!("address: {:#x} sz: {:#x}", self.clr_runtime_header.virtual_address, self.clr_runtime_header.size), None);
        data_directories_dump.push_field("Zero", format!("address: {:#x} sz: {:#x}", self.zero.virtual_address, self.zero.size), None);

        dump.push_child(data_directories_dump);

        return dump;
    }
}

#[derive(Debug, Clone)]
pub enum OptionalHeader {
    PE32(OptionalHeader32),
    PE64(OptionalHeader64),
}

impl Default for OptionalHeader {
    fn default() -> Self {
        return OptionalHeader::PE64(OptionalHeader64::default());
    }
}

impl OptionalHeader {
    pub fn dump(&self) -> Dump {
        match self {
            OptionalHeader::PE32(h) => h.dump(),
            OptionalHeader::PE64(h) => h.dump(),
        }
    }

    pub fn get_export_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.export_table,
            Self::PE64(h) => &h.export_table,
        }
    }

    pub fn get_import_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.import_table,
            Self::PE64(h) => &h.import_table,
        }
    }

    pub fn get_resource_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.resource_table,
            Self::PE64(h) => &h.resource_table,
        }
    }

    pub fn get_exception_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.exception_table,
            Self::PE64(h) => &h.exception_table,
        }
    }

    pub fn get_certificate_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.certificate_table,
            Self::PE64(h) => &h.certificate_table,
        }
    }

    pub fn get_base_relocation_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.base_relocation_table,
            Self::PE64(h) => &h.base_relocation_table,
        }
    }

    pub fn get_debug_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.debug,
            Self::PE64(h) => &h.debug,
        }
    }

    pub fn get_global_ptr_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.global_ptr,
            Self::PE64(h) => &h.global_ptr,
        }
    }

    pub fn get_tls_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.tls_table,
            Self::PE64(h) => &h.tls_table,
        }
    }

    pub fn get_load_config_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.load_config_table,
            Self::PE64(h) => &h.load_config_table,
        }
    }

    pub fn get_bound_import_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.bound_import,
            Self::PE64(h) => &h.bound_import,
        }
    }

    pub fn get_import_address_table_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.import_address_table,
            Self::PE64(h) => &h.import_address_table,
        }
    }

    pub fn get_delay_import_descriptor_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.delay_import_descriptor,
            Self::PE64(h) => &h.delay_import_descriptor,
        }
    }

    pub fn get_clr_runtime_header_idd(&self) -> &ImageDataDirectory {
        match self {
            Self::PE32(h) => &h.clr_runtime_header,
            Self::PE64(h) => &h.clr_runtime_header,
        }
    }
}

/*
 * Section Flags
 */

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SectionFlags {
    Reserved0 = 0x00000000,           // Reserved for future use.
    Reserved1 = 0x00000001,           // Reserved for future use.
    Reserved2 = 0x00000002,           // Reserved for future use.
    Reserved4 = 0x00000004,           // Reserved for future use.
    TypeNoPad = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    Reserved10 = 0x00000010, // Reserved for future use.
    CntCode = 0x00000020,   // The section contains executable code.
    CntInitializedData = 0x00000040, // The section contains initialized data.
    CntUninitializedData = 0x0000080, // The section contains uninitialized data.
    LnkOther = 0x00000100,  // Reserved for future use.
    LnkInfo = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    Reserved400 = 0x00000400, // Reserved for future use.
    LnkRemove = 0x00000800, // The section will not become part of the image. This is valid only for object files.
    LnkComdat = 0x00001000, // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    GPRel = 0x00008000,     // The section contains data referenced through the global pointer (GP).
    MemPurgeable = 0x00020000, // Reserved for future use.
    MemLocked = 0x00040000, // Reserved for future use.
    MemPreload = 0x00080000, // Reserved for future use.
    Align1Bytes = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
    Align2Bytes = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
    Align4Bytes = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
    Align8Bytes = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
    Align16Bytes = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
    Align32Bytes = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
    Align64Bytes = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
    Align128Bytes = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
    Align256Bytes = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
    Align512Bytes = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
    Align1024Bytes = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
    Align2048Bytes = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
    Align4096Bytes = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
    Align8192Bytes = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
    LnkNRelocOVFL = 0x01000000,  // The section contains extended relocations.
    MemDiscardable = 0x02000000, // The section can be discarded as needed.
    MemNotCached = 0x04000000,   // The section cannot be cached.
    MemNotPaged = 0x08000000,    // The section is not pageable.
    MemShared = 0x10000000,      // The section can be shared in memory.
    MemExecute = 0x20000000,     // The section can be executed as code.
    MemRead = 0x40000000,        // The section can be read.
    MemWrite = 0x80000000,       // The section can be written to.
}

impl SectionFlags {
    pub fn flags_as_string(section_flags: u32) -> String {
        let flags: Vec<&'static str> = SectionFlags::iter()
            .filter(|&flag| (flag as u32 & section_flags) != 0)
            .map(|flag| flag.into())
            .collect();

        return flags.join(" | ");
    }
}

/*
 * Section
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub ptr_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    fn new() -> SectionHeader {
        return SectionHeader::default();
    }

    fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<SectionHeader, Box<dyn std::error::Error>> {
        let mut header = SectionHeader::new();

        let first_name_byte = cursor.read_u8()?;

        if first_name_byte == 0x2F as u8 {
            // "/"
            todo!("Need to implement section header name finding in string table");
        } else if first_name_byte == 0x0 as u8 {
            // "\0"
            header.name = "empty".to_string();
            cursor.set_position(cursor.position() + 39);

            return Ok(header);
        } else {
            let mut name_buffer: Vec<u8> = Vec::new();

            name_buffer.push(first_name_byte);

            for _ in 0..7 {
                let c = cursor.read_u8()?;

                if c == '\0' as u8 {
                    continue;
                }

                name_buffer.push(c);
            }

            header.name = String::from_utf8(name_buffer).expect("Invalid section name found in PE");
        }

        header.virtual_size = cursor.read_u32::<LittleEndian>()?;
        header.virtual_address = cursor.read_u32::<LittleEndian>()?;
        header.size_of_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.ptr_to_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_relocations = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_line_numbers = cursor.read_u32::<LittleEndian>()?;
        header.number_of_relocations = cursor.read_u16::<LittleEndian>()?;
        header.number_of_line_numbers = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }

    pub fn data_size(&self) -> usize {
        if self.virtual_size != self.size_of_raw_data {
            return self.virtual_size as usize;
        } else {
            return self.size_of_raw_data as usize;
        }
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Section Header");

        dump.push_field("Name", self.name.clone(), None);

        dump.push_field("VirtualSize", format!("{:#x}", self.virtual_size), None);
        dump.push_field("VirtualAddress", format!("{:#x}", self.virtual_address), None);
        dump.push_field("SizeOfRawData", format!("{:#x}", self.size_of_raw_data), None);
        dump.push_field("PtrToRawData", format!("{:#x}", self.ptr_to_raw_data), None);
        dump.push_field("PointerToRelocations", format!("{:#x}", self.pointer_to_relocations), None);
        dump.push_field("PointerToLineNumbers", format!("{:#x}", self.pointer_to_line_numbers), None);
        dump.push_field("NumberOfRelocations", format!("{:#x}", self.number_of_relocations), None);
        dump.push_field("NumberOfLineNumbers", format!("{:#x}", self.number_of_line_numbers), None);
        dump.push_field("Characteristics", format!("{:#x} ({})", self.characteristics, SectionFlags::flags_as_string(self.characteristics)), None);

        return dump;
    }
}

/*
* Typical segment names:
* .text: Code
* .data: Initialized data
* .bss: Uninitialized data
* .rdata: Const/read-only (and initialized) data
* .edata: Export descriptors
* .idata: Import descriptors
* .pdata: Exception information
* .xdata: Stack unwinding information
* .reloc: Relocation table (for code instructions with absolute addressing when the module could not be loaded at its preferred base address)
* .rsrc: Resources (icon, bitmap, dialog, ...)
* .tls: __declspec(thread) data
*/

#[derive(Default, Clone)]
#[repr(C)]
pub struct Section {
    pub header: SectionHeader,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return f
            .debug_struct("Section")
            .field("header", &self.header)
            .finish();
    }
}

impl Section {
    pub fn new(header: SectionHeader, data: Vec<u8>) -> Section {
        return Section {
            header: header,
            data: data,
        };
    }

    pub fn contains_code(&self) -> bool {
        return (self.header.characteristics & (SectionFlags::CntCode as u32)) > 0;
    }

    pub fn dump(&self, disasm_code: bool) -> Dump {
        let mut dump = Dump::new_with_string(format!("Section ({})", self.header.name));

        dump.push_child(self.header.dump());

        if disasm_code {
            if self.header.characteristics & SectionFlags::CntCode as u32 > 0 {
                /* TODO: find a way to initialize a global capstone object */
                let cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .detail(false)
                    .build()
                    .expect("Failed to initialized Capstone disasm");

                let instructions = cs
                    .disasm_all(&self.data, self.header.virtual_address as u64)
                    .expect("Failed to disassemble");

                let mut code = Vec::new();

                for instruction in instructions.as_ref() {
                    if is_padding_instruction(&instruction) {
                        continue;
                    }

                    code.push(instruction.to_string());
                }

                dump.set_raw_data(DumpRawData::Code(code));
            } else {
                dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
            }
        } else {
            dump.set_raw_data(DumpRawData::Bytes(self.data.clone()));
        }

        return dump;
    }
}

/*
 * Import Directory Table
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImportDirectoryTableEntry {
    pub import_lookup_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub import_address_table_rva: u32,
}

impl ImportDirectoryTableEntry {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ImportDirectoryTableEntry, Box<dyn std::error::Error>> {
        let mut idt = ImportDirectoryTableEntry::default();

        idt.import_lookup_table_rva = cursor.read_u32::<LittleEndian>()?;
        idt.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        idt.forwarder_chain = cursor.read_u32::<LittleEndian>()?;
        idt.name_rva = cursor.read_u32::<LittleEndian>()?;
        idt.import_address_table_rva = cursor.read_u32::<LittleEndian>()?;

        return Ok(idt);
    }

    #[rustfmt::skip]
    pub fn is_zeroed_out(&self) -> bool {
        return self.import_lookup_table_rva == 0 &&
               self.time_date_stamp == 0 &&
               self.forwarder_chain == 0 &&
               self.name_rva == 0 &&
               self.import_address_table_rva == 0;
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Import Directory Table Entry");

        dump.push_field("ImportLookupTableRva", format!("{:#x}", self.import_lookup_table_rva), None);
        dump.push_field("TimeDateStamp", format!("{:#x}", self.time_date_stamp), None);
        dump.push_field("ForwarderChain", format!("{:#x}", self.forwarder_chain), None);
        dump.push_field("NameRva", format!("{:#x}", self.name_rva), None);
        dump.push_field("ImportAddressTableRva", format!("{:#x}", self.import_address_table_rva), None);

        return dump;
    }
}

#[derive(Default, Clone, Debug)]
pub struct ImportDirectoryTable {
    pub entries: Vec<ImportDirectoryTableEntry>,
}

impl ImportDirectoryTable {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ImportDirectoryTable, Box<dyn std::error::Error>> {
        let mut idt = ImportDirectoryTable::default();

        loop {
            let entry = ImportDirectoryTableEntry::from_parser(cursor)?;

            if entry.is_zeroed_out() {
                break;
            }

            idt.entries.push(entry);

            if idt.entries.len() > 256 {
                break;
            }
        }

        return Ok(idt);
    }

    pub fn len(&self) -> usize {
        return self.entries.len();
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Import Directory");

        for entry in self.entries.iter() {
            dump.push_child(entry.dump());
        }

        return dump;
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImportLookupTableEntry {
    pub by_ordinal: bool,
    pub ordinal_number: u16,
    pub hint_name_table_rva: u32,
}

impl ImportLookupTableEntry {
    pub fn new() -> ImportLookupTableEntry {
        return ImportLookupTableEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
        is_32_bits: bool,
    ) -> Result<ImportLookupTableEntry, Box<dyn std::error::Error>> {
        let mut entry = ImportLookupTableEntry::new();

        if is_32_bits {
            let data = cursor.read_u32::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x80000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        } else {
            let data = cursor.read_u64::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x8000000000000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        }

        return Ok(entry);
    }

    #[rustfmt::skip]
    pub fn is_zeroed_out(&self) -> bool {
        return self.by_ordinal == false &&
               self.ordinal_number == 0 &&
               self.hint_name_table_rva == 0;
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Import Lookup Table Entry");

        let flag_str = if self.by_ordinal { "Ordinal" } else { "Name" };

        dump.push_field("Ordinal/Name Flag", format!("{}", flag_str), None);

        if self.by_ordinal {
            dump.push_field("OrdinalNumber", format!("{:#x}", self.ordinal_number), None);
        } else {
            dump.push_field("HintNameTableRva", format!("{:#x}", self.hint_name_table_rva), None);
        }

        return dump;
    }
}

#[derive(Default, Clone, Debug)]
pub struct ImportLookupTable {
    pub entries: Vec<ImportLookupTableEntry>,
}

impl ImportLookupTable {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
        is_32_bit: bool,
    ) -> Result<ImportLookupTable, Box<dyn std::error::Error>> {
        let mut ilt = ImportLookupTable::default();

        loop {
            let entry = ImportLookupTableEntry::from_parser(cursor, is_32_bit)?;

            if entry.is_zeroed_out() {
                break;
            }

            ilt.entries.push(entry);

            if ilt.entries.len() > 256 {
                break;
            }
        }

        return Ok(ilt);
    }

    pub fn len(&self) -> usize {
        return self.entries.len();
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Import Lookup Table");

        for entry in self.entries.iter() {
            dump.push_child(entry.dump());
        }

        return dump;
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct HintNameEntry {
    pub hint: u16,
    pub name: String,
    pub pad: bool,
}

impl HintNameEntry {
    pub fn new() -> HintNameEntry {
        return HintNameEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<HintNameEntry, Box<dyn std::error::Error>> {
        let mut entry = HintNameEntry::new();

        entry.hint = cursor.read_u16::<LittleEndian>()?;

        let mut name_buffer: Vec<u8> = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        if (cursor.position() % 2) != 0 {
            cursor.read_u8()?;
            entry.pad = true;
        } else {
            entry.pad = false;
        }

        entry.name = String::from_utf8(name_buffer).expect("Invalid name found in Hint/Name Table");

        return Ok(entry);
    }
}

#[derive(Default, Clone, Debug)]
pub struct HintNameData {
    pub dll_name: String,
    pub entries: Vec<HintNameEntry>,
}

impl HintNameData {
    pub fn parse_dll_name(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut name_buffer = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        return Ok(String::from_utf8(name_buffer).expect("Invalid name found in Hint/Name Table for DLL"));
    }
}

#[derive(Default, Clone, Debug)]
pub struct HintNameTable {
    pub entries: Vec<HintNameData>,
}

impl HintNameTable {
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Hint/Name Table");

        for entry in self.entries.iter() {
            let mut dll_dump = Dump::new(&entry.dll_name);

            for hne in entry.entries.iter() {
                dll_dump.push_field("", hne.name.to_string(), None);
            }

            dump.push_child(dll_dump);
        }

        return dump;
    }

    pub fn dump_dlls(&self) -> Dump {
        let mut dump = Dump::new("DLLS");

        for entry in self.entries.iter() {
            dump.push_field("", entry.dll_name.clone(), None);
        }

        return dump;
    }
}

/*
 * Export Directory Table
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only
 */

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ExportDirectoryTable {
    pub export_flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table_rva: u32,
    pub name_pointer_rva: u32,
    pub ordinal_table_rva: u32,
}

impl ExportDirectoryTable {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ExportDirectoryTable, Box<dyn std::error::Error>> {
        let mut edt = ExportDirectoryTable::default();

        edt.export_flags = cursor.read_u32::<LittleEndian>()?;
        edt.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        edt.major_version = cursor.read_u16::<LittleEndian>()?;
        edt.minor_version = cursor.read_u16::<LittleEndian>()?;
        edt.name_rva = cursor.read_u32::<LittleEndian>()?;
        edt.ordinal_base = cursor.read_u32::<LittleEndian>()?;
        edt.address_table_entries = cursor.read_u32::<LittleEndian>()?;
        edt.number_of_name_pointers = cursor.read_u32::<LittleEndian>()?;
        edt.export_address_table_rva = cursor.read_u32::<LittleEndian>()?;
        edt.name_pointer_rva = cursor.read_u32::<LittleEndian>()?;
        edt.ordinal_table_rva = cursor.read_u32::<LittleEndian>()?;

        return Ok(edt);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Export Directory Table");

        dump.push_field("ExportFlags", format!("{:#x}", self.export_flags), None);
        dump.push_field("TimeDateStamp", format!("{:#x} ({})", self.time_date_stamp, format_u32_as_ctime(self.time_date_stamp)), None);
        dump.push_field("MajorVersion", format!("{:#x}", self.major_version), None);
        dump.push_field("MinorVersion", format!("{:#x}", self.minor_version), None);
        dump.push_field("NameRva", format!("{:#x}", self.name_rva), None);
        dump.push_field("OrdinalBase", format!("{:#x}", self.ordinal_base), None);
        dump.push_field("AddressTableEntries", format!("{:#x}", self.address_table_entries), None);
        dump.push_field("NumberOfNamePointers", format!("{:#x}", self.number_of_name_pointers), None);
        dump.push_field("ExportAddressTableRva", format!("{:#x}", self.export_address_table_rva), None);
        dump.push_field("NamePointerRva", format!("{:#x}", self.name_pointer_rva), None);
        dump.push_field("OrdinalTableRva", format!("{:#x}", self.ordinal_table_rva), None);

        return dump;
    }
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ExportAddressTableEntry {
    pub export_rva: u32,
    pub forwarder_rva: u32,
}

impl ExportAddressTableEntry {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ExportAddressTableEntry, Box<dyn std::error::Error>> {
        let mut entry = ExportAddressTableEntry::default();

        entry.export_rva = cursor.read_u32::<LittleEndian>()?;
        entry.forwarder_rva = cursor.read_u32::<LittleEndian>()?;

        return Ok(entry);
    }
}

type ExportAddressTable = Vec<ExportAddressTableEntry>;

type ExportNamePointerTable = Vec<u32>;

type ExportOrdinalTable = Vec<u16>;

type ExportNameTable = Vec<String>;

#[derive(Default, Clone, Debug)]
pub struct ExportData {
    pub export_directory_table: ExportDirectoryTable,
    pub export_address_table: ExportAddressTable,
    pub export_name_pointer_table: ExportNamePointerTable,
    pub export_ordinal_table: ExportOrdinalTable,
    pub export_name_table: ExportNameTable,
}

impl ExportData {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<ExportData, Box<dyn std::error::Error>> {
        let mut export_data = ExportData::default();

        return Ok(export_data);
    }
}

/*
 * Debug Directory
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-debug-section
 */

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum DebugType {
    Unknown = 0,               // An unknown value that is ignored by all tools.
    Coff = 1, // The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
    CodeView = 2, // The Visual C++ debug information.
    Fpo = 3, // The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
    Misc = 4, // The location of DBG file.
    Exception = 5, // A copy of .pdata section.
    FixUp = 6, // Reserved.
    OMapToSrc = 7, // The mapping from an RVA in image to an RVA in source image.
    OMapFromSrc = 8, // The mapping from an RVA in source image to an RVA in image.
    Borland = 9, // Reserved for Borland.
    Reserved10 = 10, // Reserved.
    CLSid = 11, // Reserved.
    Repro = 16, // PE determinism or reproducibility.
    EmbeddedAtPtrd = 17, // Debugging information is embedded in the PE file at location specified by PointerToRawData.
    StoresCryptoHashCnt = 19, // Stores crypto hash for the content of the symbol file used to build the PE/COFF file.
    ExDLLCharacteristics = 20, // Extended DLL characteristics bits.
}

impl From<u32> for DebugType {
    fn from(value: u32) -> Self {
        match value {
            v if v == DebugType::Unknown as u32 => DebugType::Unknown,
            v if v == DebugType::Coff as u32 => DebugType::Coff,
            v if v == DebugType::CodeView as u32 => DebugType::CodeView,
            v if v == DebugType::Fpo as u32 => DebugType::Fpo,
            v if v == DebugType::Misc as u32 => DebugType::Misc,
            v if v == DebugType::Exception as u32 => DebugType::Exception,
            v if v == DebugType::FixUp as u32 => DebugType::FixUp,
            v if v == DebugType::OMapToSrc as u32 => DebugType::OMapToSrc,
            v if v == DebugType::OMapFromSrc as u32 => DebugType::OMapFromSrc,
            v if v == DebugType::Borland as u32 => DebugType::Borland,
            v if v == DebugType::Reserved10 as u32 => DebugType::Reserved10,
            v if v == DebugType::CLSid as u32 => DebugType::CLSid,
            v if v == DebugType::Repro as u32 => DebugType::Repro,
            v if v == DebugType::EmbeddedAtPtrd as u32 => DebugType::EmbeddedAtPtrd,
            v if v == DebugType::StoresCryptoHashCnt as u32 => DebugType::StoresCryptoHashCnt,
            v if v == DebugType::ExDLLCharacteristics as u32 => DebugType::ExDLLCharacteristics,
            _ => DebugType::Unknown,
        }
    }
}

impl DebugType {
    pub fn as_static_str(&self) -> &'static str {
        return self.into();
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct DebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl DebugDirectory {
    pub fn new() -> DebugDirectory {
        return DebugDirectory::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<DebugDirectory, Box<dyn std::error::Error>> {
        let mut dd = DebugDirectory::new();

        dd.characteristics = cursor.read_u32::<LittleEndian>()?;
        dd.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        dd.major_version = cursor.read_u16::<LittleEndian>()?;
        dd.minor_version = cursor.read_u16::<LittleEndian>()?;
        dd.debug_type = cursor.read_u32::<LittleEndian>()?;
        dd.size_of_data = cursor.read_u32::<LittleEndian>()?;
        dd.address_of_raw_data = cursor.read_u32::<LittleEndian>()?;
        dd.pointer_to_raw_data = cursor.read_u32::<LittleEndian>()?;

        return Ok(dd);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Debug Directory");

        dump.push_field("Characteristics", format!("{:#x}", self.characteristics), None);
        dump.push_field("TimeDateStamp", format!("{:#x} ({})", self.time_date_stamp, format_u32_as_ctime(self.time_date_stamp)), None);
        dump.push_field("MajorVersion", format!("{:#x}", self.major_version), None);
        dump.push_field("MinorVersion", format!("{:#x}", self.minor_version), None);
        dump.push_field("DebugType", format!("{:#x} ({})",self.debug_type,DebugType::from(self.debug_type).as_static_str()), None);
        dump.push_field("SizeOfData", format!("{:#x} ({} bytes)", self.size_of_data, self.size_of_data), None);
        dump.push_field("AddressOfRawData", format!("{:#x}", self.address_of_raw_data), None);
        dump.push_field("PointerToRawData", format!("{:#x}", self.pointer_to_raw_data), None);

        return dump;
    }
}

/*
 * Exception Table
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
 */

/// 32-bit MIPS images
#[derive(Debug, Clone, Copy, Default)]
pub struct Mips32ExcFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub exception_handler: u32,
    pub handler_data: u32,
    pub prolog_end_address: u32,
}

impl Mips32ExcFunctionEntry {
    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Function Entry");

        dump.push_field("BeginAddress", format!("{:#x}", self.begin_address), None);
        dump.push_field("EndAddress", format!("{:#x}", self.end_address), None);
        dump.push_field("ExceptionHandler", format!("{:#x}", self.exception_handler), None);
        dump.push_field("HandlerData", format!("{:#x}", self.handler_data), None);
        dump.push_field("PrologEndAddress", format!("{:#x}", self.prolog_end_address), None);

        return dump;
    }
}

/// x64 and Itanium platforms
#[derive(Debug, Clone, Copy, Default)]
pub struct X64ExcFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_information: u32,
}

impl X64ExcFunctionEntry {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<X64ExcFunctionEntry, Box<dyn std::error::Error>> {
        let mut entry = X64ExcFunctionEntry::default();

        entry.begin_address = cursor.read_u32::<LittleEndian>()?;
        entry.end_address = cursor.read_u32::<LittleEndian>()?;
        entry.unwind_information = cursor.read_u32::<LittleEndian>()?;

        return Ok(entry);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Function Entry");

        dump.push_field("BeginAddress", format!("{:#x}", self.begin_address), None);
        dump.push_field("EndAddress", format!("{:#x}", self.end_address), None);
        dump.push_field("UnwindInformation", format!("{:#x}", self.unwind_information), None);

        return dump;
    }
}

/// ARM, PowerPC, SH3/SH4 Windows CE platforms
#[derive(Debug, Clone, Copy, Default)]
pub struct OtherExcFunctionEntry {
    pub begin_address: u32,
    pub prolog_length: u8,
    pub function_length: u32,
    pub flag_32bit: bool,
    pub flag_exception: bool,
}

impl OtherExcFunctionEntry {
    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("Function Entry");

        dump.push_field("BeginAddress", format!("{:#x}", self.begin_address), None);
        dump.push_field("PrologLength", format!("{:#x}", self.prolog_length), None);
        dump.push_field("FunctionLength", format!("{:#x}", self.function_length), None);
        dump.push_field("32-bit Flag", format!("{}", self.flag_32bit), None);
        dump.push_field("Exception Flag", format!("{}", self.flag_exception), None);

        return dump;
    }
}

#[derive(Debug, Clone)]
pub enum ExcFunctionEntry {
    Mips32(Mips32ExcFunctionEntry),
    X64(X64ExcFunctionEntry),
    Other(OtherExcFunctionEntry),
}

impl Default for ExcFunctionEntry {
    fn default() -> Self {
        return ExcFunctionEntry::X64(X64ExcFunctionEntry::default());
    }
}

impl ExcFunctionEntry {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
        machine_type: MachineType,
    ) -> Result<ExcFunctionEntry, Box<dyn std::error::Error>> {
        match machine_type {
            MachineType::AMD64 | MachineType::I386 => Ok(ExcFunctionEntry::X64(
                X64ExcFunctionEntry::from_parser(cursor)?,
            )),
            _ => Err("Cannot parse Exception Function Entry, unsupported platform".into()),
            /* TODO: implement other machine types */
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ExcFunctionEntry::Mips32(_) => 20,
            ExcFunctionEntry::X64(_) => 12,
            ExcFunctionEntry::Other(_) => 8,
        }
    }

    pub fn dump(&self) -> Dump {
        match self {
            ExcFunctionEntry::Mips32(e) => e.dump(),
            ExcFunctionEntry::X64(e) => e.dump(),
            ExcFunctionEntry::Other(e) => e.dump(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExceptionTable {
    pub entries: Vec<ExcFunctionEntry>,
}

impl ExceptionTable {
    pub fn from_parser(
        cursor: &mut io::Cursor<&Vec<u8>>,
        size: usize,
        machine_type: MachineType,
    ) -> Result<ExceptionTable, Box<dyn std::error::Error>> {
        let mut et = ExceptionTable::default();

        let mut parsed_sz = 0 as usize;

        while parsed_sz < size {
            let entry = ExcFunctionEntry::from_parser(cursor, machine_type)?;
            parsed_sz += entry.len();
            et.entries.push(entry);
        }

        return Ok(et);
    }

    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new(
            format!("Exception Table ({} entries)", self.entries.len()).as_str(),
        );

        for entry in self.entries.iter() {
            dump.push_child(entry.dump());
        }

        return dump;
    }
}

/*
 * PE Header
 */

#[derive(Clone, Debug, Default)]
pub struct PEHeader {
    dos: DOSHeader,
    nt: NTHeader,
    optional: OptionalHeader,
}

/*
 * PE
 */

pub enum PEArchitecture {
    PE32,
    PE64,
}

#[derive(Default, Debug)]
pub struct PE {
    pub header: PEHeader,
    pub sections: HashMap<String, Section>,
    pub import_directory_table: Option<ImportDirectoryTable>,
    pub import_lookup_tables: Option<Vec<ImportLookupTable>>,
    pub hint_name_table: Option<HintNameTable>,
    pub debug_directory: Option<DebugDirectory>,
    pub exception_table: Option<ExceptionTable>,
}

impl PE {
    pub fn new() -> PE {
        return PE::default();
    }

    pub fn get_architecture(&self) -> PEArchitecture {
        match &self.header.optional {
            OptionalHeader::PE32(_) => return PEArchitecture::PE32,
            OptionalHeader::PE64(_) => return PEArchitecture::PE64,
        }
    }

    pub fn is_32_bits(&self) -> bool {
        match &self.header.optional {
            OptionalHeader::PE32(_) => return true,
            OptionalHeader::PE64(_) => return false,
        }
    }

    pub fn get_size_of_optional_header(&self) -> u64 {
        return self.header.nt.coff_header.size_of_optional_header as u64;
    }

    pub fn get_dos_header(&self) -> &DOSHeader {
        return &self.header.dos;
    }

    pub fn get_optional_header(&self) -> &OptionalHeader {
        return &self.header.optional;
    }

    pub fn get_nt_header(&self) -> &NTHeader {
        return &self.header.nt;
    }

    pub fn get_number_of_sections(&self) -> usize {
        return self.header.nt.coff_header.number_of_sections as usize;
    }

    pub fn convert_rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        for section in self.sections.values() {
            let start = section.header.virtual_address;
            let end = start + section.header.virtual_size;

            if rva >= start && rva < end {
                let offset_in_section = (rva - start) as u64;
                return Some(section.header.ptr_to_raw_data as u64 + offset_in_section);
            }
        }

        return None;
    }

    pub fn parse_headers_and_sections(
        &mut self,
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dos_header = DOSHeader::from_parser(cursor)?;

        cursor.set_position(dos_header.e_lfanew as u64);

        let nt_header = NTHeader::from_parser(cursor)?;

        let optional_magic: u16 = cursor.read_u16::<LittleEndian>()?;
        cursor.set_position(cursor.position() - 2);

        let start_of_optional_position = cursor.position();

        match optional_magic {
            PE_FORMAT_32_MAGIC => {
                let optional_header: OptionalHeader32 = OptionalHeader32::from_parser(cursor)?;

                self.header = PEHeader {
                    dos: dos_header,
                    nt: nt_header,
                    optional: OptionalHeader::PE32(optional_header),
                };
            }
            PE_FORMAT_64_MAGIC => {
                let optional_header: OptionalHeader64 = OptionalHeader64::from_parser(cursor)?;

                self.header = PEHeader {
                    dos: dos_header,
                    nt: nt_header,
                    optional: OptionalHeader::PE64(optional_header),
                };
            }
            _ => {
                return Err("Invalid PE optional header magic".into());
            }
        }

        let end_of_optional_position = cursor.position();
        let optional_size = end_of_optional_position - start_of_optional_position;

        cursor
            .set_position(cursor.position() + (self.get_size_of_optional_header() - optional_size));

        for _ in 0..self.get_number_of_sections() {
            let section_header = SectionHeader::from_parser(cursor)?;

            let previous_position = cursor.position();

            let mut section_data: Vec<u8> = vec![0; section_header.data_size()];

            cursor.set_position(section_header.ptr_to_raw_data as u64);
            cursor.read_exact(&mut section_data)?;

            self.sections.insert(
                section_header.name.clone(),
                Section {
                    header: section_header,
                    data: section_data,
                },
            );

            cursor.set_position(previous_position);
        }

        return Ok(());
    }

    pub fn parse_import_data(
        &mut self,
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let import_table_idd = self.get_optional_header().get_import_table_idd();
        let itd_file_offset = self.convert_rva_to_file_offset(import_table_idd.virtual_address);

        if let Some(file_offset) = itd_file_offset {
            cursor.set_position(file_offset);

            let import_directory_table = ImportDirectoryTable::from_parser(cursor)?;
            let mut hint_name_table = HintNameTable::default();

            let mut import_lookup_tables = Vec::new();

            for idt in import_directory_table.entries.iter() {
                let ilt_offset = self.convert_rva_to_file_offset(idt.import_lookup_table_rva).expect("Cannot find file offset for Import Lookup Table");
                cursor.set_position(ilt_offset);

                let ilt = ImportLookupTable::from_parser(cursor, self.is_32_bits())?;

                let mut hnd = HintNameData::default();

                let dll_name_offset = self.convert_rva_to_file_offset(idt.name_rva).expect("Cannot find file offset_for_dll_name");

                cursor.set_position(dll_name_offset);

                hnd.dll_name = HintNameData::parse_dll_name(cursor)?;

                for ilt_entry in ilt.entries.iter() {
                    if ilt_entry.by_ordinal {
                        continue
                    }

                    let ilt_offset = self.convert_rva_to_file_offset(ilt_entry.hint_name_table_rva).expect("Cannot find file offset for Hint/Name table entry");

                    cursor.set_position(ilt_offset);

                    hnd.entries.push(HintNameEntry::from_parser(cursor)?);
                }

                hint_name_table.entries.push(hnd);

                import_lookup_tables.push(ilt);
            }

            self.import_directory_table = Some(import_directory_table);
            self.import_lookup_tables = Some(import_lookup_tables);
            self.hint_name_table = Some(hint_name_table);
        }

        return Ok(());
    }

    #[allow(dead_code)]
    pub fn parse_export_data(
        &mut self,
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let export_table_idd = self.get_optional_header().get_export_table_idd();
        let etd_offset = self.convert_rva_to_file_offset(export_table_idd.virtual_address);

        if let Some(file_offset) = etd_offset {
            cursor.set_position(file_offset);

            let edt = ExportDirectoryTable::from_parser(cursor)?;
        }

        return Ok(());
    }

    pub fn parse_debug_directory(
        &mut self,
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let debug_va = self.get_optional_header().get_debug_idd().virtual_address;

        if debug_va > 0 {
            let debug_fo = self.convert_rva_to_file_offset(debug_va);

            if let Some(dfo) = debug_fo {
                cursor.set_position(dfo as u64);

                let debug_directory = DebugDirectory::from_parser(cursor)?;

                self.debug_directory = Some(debug_directory);
            }
        }

        return Ok(());
    }

    pub fn parse_exception_table(
        &mut self,
        cursor: &mut io::Cursor<&Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exception_va = self
            .get_optional_header()
            .get_exception_table_idd()
            .virtual_address;

        if exception_va > 0 {
            let exception_fo = self.convert_rva_to_file_offset(exception_va);

            if let Some(efo) = exception_fo {
                cursor.set_position(efo as u64);

                let exception_table = ExceptionTable::from_parser(
                    cursor,
                    self.get_optional_header().get_exception_table_idd().size as usize,
                    self.get_nt_header().coff_header.machine.into(),
                )?;

                self.exception_table = Some(exception_table);
            }
        }

        return Ok(());
    }
}

/*
 * Main parse method that reads from a file, tests if it's a PE file or not, parses and returns the parsed PE
 */
pub fn parse_pe(file_path: &PathBuf) -> Result<PE, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_path_str: &str = file_path.to_str().expect("Cannot convert file_path to str");

    if !file_path_str.ends_with(".exe") && !file_path_str.ends_with(".dll") {
        return Err("File is not a Portable Executable (.exe | .dll)".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open file");
    let mut cursor = io::Cursor::new(&file_bytes);

    let mut pe: PE = PE::new();

    pe.parse_headers_and_sections(&mut cursor)?;
    pe.parse_import_data(&mut cursor)?;
    pe.parse_export_data(&mut cursor)?;
    pe.parse_debug_directory(&mut cursor)?;
    pe.parse_exception_table(&mut cursor)?;

    return Ok(pe);
}
