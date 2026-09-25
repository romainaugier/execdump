# execdump

execdump is a command-line tool that helps you analyze Windows's PE, Linux's ELF and macOS's Mach-O files (x86, x86_64 and aarch64) by parsing and printing the required information about them, or navigate through them using a terminal-based ui.

This project is currently a work in progress so not everything is supported, and it might be broken.

The goal is to provide a fast, reliable and cross-platform reverse-engineering application.

execdump might evolve into a library later, instead of just being a standalone command-line tool.

## Usage

```
Usage: execdump.exe [OPTIONS] <FILE_PATH>

Arguments:
  <FILE_PATH>

Options:
  -t, --tui
          Opens the executable in the terminal-based user interface for exploration

      --pe-dos-header
          Dumps the PE legacy MS-DOS compatible header
      --pe-nt-header
          Dumps the PE NT Header (most recent)
      --pe-optional-header
          Dumps the PE Optional (either 32/64) header
      --pe-import
          Dump all the PE data related to imports, if any
      --pe-import-directory-table
          Dump the Import Directory Table, if any
      --pe-hint-name-table
          Dump the Hint/Name Table, if any
      --pe-dlls
          Dump the DLLs names imported, if any
      --pe-export
          Dump all the PE data related to exports, if any
      --pe-debug-directory
          Dump the debug information from the Debug Directory, if any
      --pe-exc-table
          Dump the exception information from the Exception Table, if any

      --elf-headers
          Dumps all the ELF headers
      --elf-header
          Dumps the ELF Base Header
      --elf-program-headers
          Dumps the ELF Program Headers
      --elf-symbols
          Dumps the ELF Symbol Tables (.symtab and .dynsym), if any
      --elf-dynamic
          Dumps the ELF Dynamic Section, if any
      --elf-relocations
          Dumps the ELF Relocation Tables, if any
      --elf-imports
          Dumps the ELF imported libraries and symbols, if any
      --elf-notes
          Dumps the ELF Notes, if any

      --macho-fat-header
          Dumps the Mach-O Fat (Universal) Header, if any
      --macho-header
          Dumps the Mach-O Header of each architecture
      --macho-load-commands
          Dumps the Mach-O Load Commands of each architecture
      --macho-symbols
          Dumps the Mach-O Symbol Table of each architecture, if any
      --macho-imports
          Dumps the Mach-O imported libraries and symbols of each architecture, if any

      --sections
          Dumps the Sections
      --sections-filter <SECTIONS_FILTER>
          Regulax expresion to filter the Sections to display [default: .*]
      --sections-data
          Dumps the Sections data along with the headers

      --disasm
          Disassemble the code found in the Sections containing code
      --decompile <DECOMPILE>
          Analyze the code and output the requested decompilation stages (comma separated):
          functions (recovered functions list), cfg (control flow graphs as Graphviz dot),
          callgraph (call graph as Graphviz dot) [possible values: functions, cfg, callgraph]
      --functions-filter <FUNCTIONS_FILTER>
          Regular expression to filter the functions (by name or hexadecimal address) used by --decompile [default: .*]

      --padding-size <PADDING_SIZE>
          Padding size to apply when dumping information for better readability [default: 4]

  -h, --help
          Print help
  -V, --version
          Print version
```

## Features

### PE

Headers:

- :heavy_check_mark: DOS
- :heavy_check_mark: NT-Header (and COFF Header)
- :heavy_check_mark: Optional Header (32-bit and 64-bit)

Sections:

- :heavy_check_mark: Export Table
- :heavy_check_mark: Import Table
- :x: Resource Table
- :heavy_check_mark: Exception Table
- :x: Certificate Table
- :x: Base Relocation Table
- :heavy_check_mark: Debug
- :x: TLS Table
- :x: Load Config Table
- :x: Bound Import Table
- :x: Import Address Table
- :x: Delay Import Descriptor
- :x: CLR Runtime Header

Code:

- :heavy_check_mark: Basic disassembly of the code sections

### ELF

Headers:

- :heavy_check_mark: ELF Header
- :heavy_check_mark: Program Headers (and interpreter)
- :heavy_check_mark: Section Headers

Sections:

- :heavy_check_mark: Symbol Tables (.symtab, .dynsym)
- :heavy_check_mark: Dynamic Section
- :heavy_check_mark: Relocations (.rel, .rela)
- :heavy_check_mark: Imports (needed libraries and imported symbols)
- :heavy_check_mark: Notes (build-id, ABI tag, GNU properties)
- :x: Symbol Versioning (.gnu.version, .gnu.version_r)
- :x: DWARF debug information

Code:

- :heavy_check_mark: Basic disassembly of the code sections

### Mach-O

Headers:

- :heavy_check_mark: Fat (Universal) Header
- :heavy_check_mark: Mach Header (32-bit and 64-bit)

Load Commands:

- :heavy_check_mark: Segments and Sections
- :heavy_check_mark: Symbol Table and Dynamic Symbol Table
- :heavy_check_mark: Dylibs, Dylinker and Rpaths
- :heavy_check_mark: Main, UUID, Build Version, Version Min, Source Version
- :heavy_check_mark: Dyld Info, Function Starts, Chained Fixups, Exports Trie, Code Signature (offsets only)
- :x: Dyld bind/rebase opcodes, chained fixups and exports trie contents
- :x: Code Signature contents

Code:

- :heavy_check_mark: Basic disassembly of the code sections

### Architectures

Disassembly:

- :heavy_check_mark: x86
- :heavy_check_mark: x86_64
- :heavy_check_mark: aarch64
- :x: arm (32-bit)

### Core

Utilities:
  - :heavy_check_mark: Symbol Demangler: Itanium C++ ABI (GCC/Clang on Linux, macOS, MinGW), MSVC (Windows x86, x64, ARM64, ARM64EC) and Rust legacy
  - :x: Known symbols loading (kernel32, user32, glibc...)

Analysis:
  - :heavy_check_mark: Format-agnostic program model (memory map, symbols, imports, entry point)
  - :heavy_check_mark: Function discovery by recursive descent, seeded by the entry point, symbols, exports, PE exception table (.pdata), Mach-O LC_FUNCTION_STARTS, ELF .eh_frame and init arrays, then call targets and code references (works on stripped binaries)
  - :heavy_check_mark: Control flow graphs (true/false branches, tail calls, x86 jump tables)
  - :heavy_check_mark: Noreturn functions (known names and propagation)
  - :heavy_check_mark: Imports resolution through PLT entries, Mach-O stubs, IAT thunks and indirect calls (aarch64 adrp/ldr tracking)
  - :heavy_check_mark: Call graph and cross references
  - :heavy_check_mark: Strings (ASCII, UTF-16 for PE) and references annotations
  - :x: aarch64 jump tables

Decompiler:
  - :heavy_check_mark: CFG recovery
  - :x: SSA construction
  - :x: Data-flow analysis
  - :x: Control-flow structuring
  - :x: Expression recovery
  - :x: Type recovery
  - :x: Variable recovery
  - :x: High-level cleanup passes
  - :x: C code generation

### TUI

Viewers:
  - :heavy_check_mark: Headers
  - :heavy_check_mark: PE Sections
  - :heavy_check_mark: ELF Sections
  - :heavy_check_mark: Mach-O Sections
  - :heavy_check_mark: Hex Viewer
  - :heavy_check_mark: Disasm Viewer (linear, with function labels and annotations)
  - :heavy_check_mark: Control flow graph viewer (radare2-like node graph)
  - :heavy_check_mark: Call graph viewer
  - :heavy_check_mark: Functions, strings, imports and memory map tables
  - :x: Decompiler Viewer

The analysis runs in the background when the TUI starts, its progress is shown in the title bar.

Key bindings (vim-like, the main ones can be changed in `~/.execdumprc`):

| Keys | Action |
|---|---|
| `Tab` | Switch between the explorer and the content |
| `e` | Show/hide the explorer |
| `:` | Command line: an address (`:0x401000`), a function name (`:main`), `callgraph [function]`, `functions`, `strings`, `imports`, `sections`, `entry`, `depth <n>`, `q` |
| `/` | Search: filters the tables, finds the next matching node or line |
| `Ctrl-o` / `Backspace` | Go back to the previous view |
| `Ctrl-r` (or `Ctrl-i` when the terminal can tell it apart from `Tab`) | Go forward |
| `?` | Help |
| `q` | Quit |

In the graphs:

| Keys | Action |
|---|---|
| `h` `j` `k` `l` | Scroll by one cell (`H` `J` `K` `L` scroll faster, `Ctrl-d` / `Ctrl-u` by half a page) |
| `n` / `p` | Next / previous node (top to bottom, left to right) |
| `g` / `G` | First / last node |
| `t` / `f` | Follow the true / false branch of the selected block |
| `c` | Center on the selected node |
| `Enter` | Go to a function called from the selected block / open the selected function of the call graph |
| `Space` | Switch between the graph and the linear disassembly of the function |
| `x` | Cross references to the function |
| `C` | Call graph from the function |
| `+` / `-` / `i` / `r` | Call graph depth / show imports / re-root at the selected function |

Edges colors: green for a taken conditional branch (`t`), red for a conditional branch not taken (`f`), blue for unconditional jumps, grey for fall-through, purple for jump table entries. In the call graph, dashed edges are tail calls (purple) and functions referenced by address (grey).

```toml
# ~/.execdumprc
quit = 'q'
down = 'j'
up = 'k'
left = 'h'
right = 'l'
next_node = 'n'
prev_node = 'p'
follow_true = 't'
follow_false = 'f'
```

![tui](https://github.com/romainaugier/execdump/blob/main/res/tui.png)

## Acknowledgement

This tool is based on several amazing open-source projects (go check them out!) :
 - [Capstone](https://github.com/capstone-engine/capstone)
 - [Ratatui](https://ratatui.rs/)
