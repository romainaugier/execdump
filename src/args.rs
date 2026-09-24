use clap::Parser;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Parser/Dumper for executable files (PE, ELF and Mach-O)")]
pub struct Args {
    /// Opens the executable in the terminal-based user interface for exploration
    #[arg(long, short, default_value_t = false)]
    pub tui: bool,

    /*
     * PE
     */

    /// Dumps all the PE headers
    #[arg(long, default_value_t = false)]
    pub pe_headers: bool,

    /// Dumps the PE legacy MS-DOS compatible header
    #[arg(long, default_value_t = false)]
    pub pe_dos_header: bool,

    /// Dumps the PE NT Header (most recent)
    #[arg(long, default_value_t = false)]
    pub pe_nt_header: bool,

    /// Dumps the PE Optional (either 32/64) header
    #[arg(long, default_value_t = false)]
    pub pe_optional_header: bool,

    /// Dump all the PE data related to imports, if any
    #[arg(long, default_value_t = false)]
    pub pe_import: bool,

    /// Dump the Import Directory Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_import_directory_table: bool,

    /// Dump the Hint/Name Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_hint_name_table: bool,

    /// Dump the DLLs names imported, if any
    #[arg(long, default_value_t = false)]
    pub pe_dlls: bool,

    /// Dump all the PE data related to exports, if any
    #[arg(long, default_value_t = false)]
    pub pe_export: bool,

    /// Dump the debug information from the Debug Directory, if any
    #[arg(long, default_value_t = false)]
    pub pe_debug_directory: bool,

    /// Dump the exception information from the Exception Table, if any
    #[arg(long, default_value_t = false)]
    pub pe_exc_table: bool,

    /*
     * ELF
     */

    /// Dumps all the ELF headers
    #[arg(long, default_value_t = false)]
    pub elf_headers: bool,

    /// Dumps the ELF Base Header
    #[arg(long, default_value_t = false)]
    pub elf_header: bool,

    /// Dumps the ELF Program Headers
    #[arg(long, default_value_t = false)]
    pub elf_program_headers: bool,

    /// Dumps the ELF Symbol Tables (.symtab and .dynsym), if any
    #[arg(long, default_value_t = false)]
    pub elf_symbols: bool,

    /// Dumps the ELF Dynamic Section, if any
    #[arg(long, default_value_t = false)]
    pub elf_dynamic: bool,

    /// Dumps the ELF Relocation Tables, if any
    #[arg(long, default_value_t = false)]
    pub elf_relocations: bool,

    /// Dumps the ELF imported libraries and symbols, if any
    #[arg(long, default_value_t = false)]
    pub elf_imports: bool,

    /// Dumps the ELF Notes, if any
    #[arg(long, default_value_t = false)]
    pub elf_notes: bool,

    /*
     * Mach-O
     */

    /// Dumps the Mach-O Fat (Universal) Header, if any
    #[arg(long, default_value_t = false)]
    pub macho_fat_header: bool,

    /// Dumps the Mach-O Header of each architecture
    #[arg(long, default_value_t = false)]
    pub macho_header: bool,

    /// Dumps the Mach-O Load Commands of each architecture
    #[arg(long, default_value_t = false)]
    pub macho_load_commands: bool,

    /// Dumps the Mach-O Symbol Table of each architecture, if any
    #[arg(long, default_value_t = false)]
    pub macho_symbols: bool,

    /// Dumps the Mach-O imported libraries and symbols of each architecture, if any
    #[arg(long, default_value_t = false)]
    pub macho_imports: bool,

    /*
     * Common
     */

    /// Dumps the Sections
    #[arg(long, default_value_t = false)]
    pub sections: bool,

    /// Regulax expresion to filter the Sections to display
    #[arg(long, default_value = ".*")]
    pub sections_filter: String,

    /// Dumps the Sections data along with the headers
    #[arg(long, default_value_t = false)]
    pub sections_data: bool,

    /// Disassemble the code found in the Sections containing code
    #[arg(long, default_value_t = false)]
    pub disasm: bool,

    /// Decompile the code found in the Sections containing code.
    /// It will override disasm if not set
    #[arg(long, default_value_t = false)]
    pub decompile: bool,

    /*
     * Formatting
     */

    /// Padding size to apply when dumping information for better readability
    #[arg(long, default_value_t = 4)]
    pub padding_size: usize,

    pub file_path: PathBuf,
}
