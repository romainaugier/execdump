// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, ValueEnum};

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Parser/Dumper for executable files (PE, ELF and Mach-O)")]
pub struct Args {
    /// Opens the executable in the terminal-based user interface for exploration
    #[arg(long, short, default_value_t = false)]
    pub tui: bool,

    /// Prints the build, machine and platform specs to paste in bug reports, then exits
    #[arg(long, default_value_t = false)]
    pub specs: bool,

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

    /// Dump the delay load imports (their DLLs, functions and slots), if any
    #[arg(long, default_value_t = false)]
    pub pe_delay_imports: bool,

    /// Dump the TLS Directory and its callbacks, if any
    #[arg(long, default_value_t = false)]
    pub pe_tls: bool,

    /// Dump the Load Configuration (security cookie, Control Flow Guard functions), if any
    #[arg(long, default_value_t = false)]
    pub pe_load_config: bool,

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

    /// Dumps the pointers dyld writes of each architecture (chained fixups, binds), if any
    #[arg(long, default_value_t = false)]
    pub macho_fixups: bool,

    /// Dumps the Mach-O exported symbols of each architecture (exports trie), if any
    #[arg(long, default_value_t = false)]
    pub macho_exports: bool,

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

    /// Analyze the code and output the requested decompilation stages (comma separated):
    /// functions (recovered functions list), cfg (control flow graphs as Graphviz dot),
    /// callgraph (call graph as Graphviz dot), llvm (optimized LLVM IR of the functions), c (decompiled C code), storage (where the variables are while the functions run)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub decompile: Vec<DecompileOutput>,

    /// Regular expression to filter the functions (by name or hexadecimal address) used by --decompile
    #[arg(long, default_value = ".*")]
    pub functions_filter: String,

    /// Improves the decompiled C code with the LLM of the [llm] section of ~/.daedalerc
    /// (names, types and a summary of each function, the callees first)
    #[arg(long, default_value_t = false)]
    pub llm: bool,

    /*
     * Projects
     */

    /// Project directory (annotations, modules, edited code and their history), next to the binary
    /// by default (<FILE_PATH>.ddproj, or the <FILE_PATH>.edproj of execdump when only it exists)
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Decompiles every function with the annotations of the project and writes the C code as a source
    /// tree (one file per module in src/, their headers in include/)
    #[arg(long)]
    pub export: Option<PathBuf>,

    /*
     * Formatting
     */

    /// Padding size to apply when dumping information for better readability
    #[arg(long, default_value_t = 4)]
    pub padding_size: usize,

    #[arg(required_unless_present = "specs")]
    pub file_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DecompileOutput {
    /// List of the recovered functions
    Functions,
    /// Control flow graphs of the functions (Graphviz dot)
    Cfg,
    /// Call graph (Graphviz dot)
    Callgraph,
    /// Optimized LLVM IR of the functions
    Llvm,
    /// Decompiled C code of the functions
    C,
    /// Where the variables of the functions are while they run (registers and stack slots, by addresses)
    Storage,
}
