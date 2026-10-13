# execdump

execdump is a command-line tool that helps you analyze Windows's PE, Linux's ELF and macOS's Mach-O files (x86, x86_64 and aarch64) by parsing and printing the required information about them, or navigate through them using a terminal-based ui.

This project is currently a work in progress so not everything is supported, and it might be broken.

The goal is to provide a fast, reliable and cross-platform reverse-engineering application.

execdump might evolve into a library later, instead of just being a standalone command-line tool.

## Building

The decompiler lifts the code to LLVM IR and links LLVM 18 statically: building needs the LLVM 18 development
libraries (`llvm-config` and the static libraries), found through `LLVM_SYS_181_PREFIX` or the `PATH`.

- Debian/Ubuntu: `apt install llvm-18-dev libpolly-18-dev libzstd-dev zlib1g-dev`
- macOS: `brew install llvm@18 zstd`, then `export LLVM_SYS_181_PREFIX=$(brew --prefix llvm@18)`
- Windows: a static LLVM build such as [llvm-package-windows](https://github.com/vovkos/llvm-package-windows), then set `LLVM_SYS_181_PREFIX`

```
cargo build --release
```

The time spent in each stage of a project (analysis, background decompilation, cache, modules, export) on a binary:

```
cargo run --release -p execdump-project --example profile -- /usr/bin/python3 [workers] [max seconds of decompilation]
```

Every function of some binaries decompiled with overflow checks, the panics grouped by where they happen
(`SWEEP_TRACE=1` prints each function before it is decompiled, `SWEEP_WORKERS` sets the number of threads and
`SWEEP_STACK` their stack size, a small one finds the deepest recursions):

```
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    cargo run --release --target-dir target/checked -p execdump-project --example sweep -- /usr/bin/*
```

A function whose decompilation panics shows the panic as its error (`decompilation failed: panicked at ...`), the other
functions are not affected. A crash of execdump itself gives the terminal back before printing the error, the fatal
errors that are not panics (stack overflows, invalid memory accesses) included on Unix. The analysis and the decompiler
run on threads with large stacks (512 MB reserved, only what is used is allocated): debug builds recurse deeply on big
functions, and are much slower, `--release` is the way to explore large binaries.

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
          callgraph (call graph as Graphviz dot), llvm (optimized LLVM IR), c (decompiled C code)
          [possible values: functions, cfg, callgraph, llvm, c]
      --functions-filter <FUNCTIONS_FILTER>
          Regular expression to filter the functions (by name or hexadecimal address) used by --decompile [default: .*]
      --llm
          Improves the decompiled C code with the LLM of the [llm] section of ~/.execdumprc

      --project <PROJECT>
          Project directory (annotations, modules, edited code and their history), next to the binary by default (<FILE_PATH>.edproj)
      --export <EXPORT>
          Decompiles every function with the annotations of the project and writes the C code as a source tree
          (one file per module in src/, their headers in include/)

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
  - :heavy_check_mark: Symbol Demangler: Itanium C++ ABI (GCC/Clang on Linux, macOS, MinGW), MSVC (Windows x86, x64, ARM64, ARM64EC), Rust legacy and Rust v0 (checked against llvm-cxxfilt on the 100k Rust symbols of execdump)
  - :heavy_check_mark: Shared libraries a binary needs, found where the loader looks for them (ELF: RPATH, LD_LIBRARY_PATH, RUNPATH, ld.so.conf, default directories; PE: next to the binary, PATH; Mach-O: @rpath, @loader_path, @executable_path)
  - :heavy_check_mark: Type database parsed from C headers: prototypes, typedefs, structs (with layouts), unions and enums, bundled for glibc and Win32 (mingw-w64)

Analysis:
  - :heavy_check_mark: Format-agnostic program model (memory map, symbols, imports, entry point)
  - :heavy_check_mark: Function discovery by recursive descent, seeded by the entry point, symbols, exports, PE exception table (.pdata), Mach-O LC_FUNCTION_STARTS, ELF .eh_frame and init arrays, then call targets and code references (works on stripped binaries)
  - :heavy_check_mark: Control flow graphs (true/false branches, tail calls, x86 jump tables)
  - :heavy_check_mark: Functions split by the compiler (hot and cold parts): the jumps between the parts do not create
    functions in the middle of others, the code reached only from a cold part is a fragment that stops at the code
    already recovered (no copies of the rest of the function)
  - :heavy_check_mark: Noreturn functions (known names and propagation)
  - :heavy_check_mark: Imports resolution through PLT entries, Mach-O stubs, IAT thunks and indirect calls (aarch64 adrp/ldr tracking)
  - :heavy_check_mark: Call graph and cross references
  - :heavy_check_mark: Strings (ASCII, UTF-16 for PE) and references annotations
  - :x: aarch64 jump tables

Decompiler:
  - :heavy_check_mark: CFG recovery
  - :heavy_check_mark: Lifting to LLVM IR (x86, x86_64, aarch64), with lazy flags and a statically tracked stack frame
  - :heavy_check_mark: SSA construction and data-flow cleanups (LLVM passes)
  - :heavy_check_mark: Signature recovery (C headers, demangled C++ symbols, then used argument registers and their widths)
  - :heavy_check_mark: Control-flow structuring (if/else, loops, switches with jump tables, short-circuit conditions, tail duplication of the returns)
  - :heavy_check_mark: Expression recovery (out of SSA, divisions by constants, struct fields from the type database)
  - :heavy_check_mark: Type recovery (pointers and their pointees, signedness, prototypes)
  - :heavy_check_mark: Variable recovery (loop variables coalescing, names from their use)
  - :heavy_check_mark: C code generation (`--decompile c`)
  - :heavy_check_mark: Address of the statements: each machine instruction is the debug location of the LLVM instructions
    lifted from it, which the passes keep, so nearly every line of C has the address it comes from (the gutter of the C
    views, and the synchronization of the C code with the disassembly and the graph)
  - :heavy_check_mark: Strings and constants: addresses of strings are string literals (the ones passed to functions even when they end
    another string, linkers merge them), loads from constant addresses of read-only data are their value (numbers,
    floating point numbers, strings, functions)
  - :heavy_check_mark: LLM improvement pass (`--llm`, `L` in the TUI as a proposal to review): names of the unnamed functions and of the variables, types and a summary, validated before being applied (callees first, their new names show in their callers)
  - :heavy_check_mark: User annotations followed by the decompiler: names of the functions and globals, prototypes, variables

### Projects

The C code of the whole program is a project: every function is decompiled in the background, organized in modules
(source files), annotated and edited, and the work is saved in a git repository next to the binary.

- :heavy_check_mark: Background decompilation of every function, callees first, the functions on screen before the others
  (one decompiler per core but one, sharing the signatures they discover), progress in the title bar
- :heavy_check_mark: Decompilation cache on disk (`~/.cache/execdump/<id of the binary>/`): reopening a binary does not
  decompile it again, a function is decompiled again only when its annotations, or the names and prototypes of what it
  calls, change (or when execdump is rebuilt). Another execdump opening the same binary at the same time keeps its cache
  in memory.
- :heavy_check_mark: Modules found automatically: the paths of the Rust items (`crate::module::Type::method` is in
  `crate/module.rs`, impls in the module of their type), ELF FILE symbols (object files of the local functions), functions between
  two functions of the same object file (linkers lay object files out contiguously), C++ namespaces and classes, then a
  default module named after the binary. Functions are moved between modules by the user (or the LLM).
- :heavy_check_mark: Annotations: names of the functions and globals (callers and callees follow), prototypes, names and
  types of the variables, summaries
- :heavy_check_mark: Edited code: the edits are kept with the decompiled text they were made on, and rebased when the
  decompiler renders the function differently: renames are applied to the edited text, other changes are merged by
  libgit2 (conflicts are marked as in git and resolved in the code)
- :heavy_check_mark: LLM proposals (names, types and summary of a function, organization of the functions in modules),
  reviewed as diffs before being accepted
- :heavy_check_mark: Export of the modules as a source tree: `src/<module>` and `include/<module>.h` (prototypes of the
  functions), `include/execdump.h` (`undefined` types), `include/execdump_imports.h` and `include/execdump_globals.h`.
  The tree is meant to be read and built upon, it does not always compile as it is.

The project directory (`<binary>.edproj` by default, `--project` or `:w <dir>` to choose another one) holds a bare git
repository (`repo.git`) and the session (`session.toml`, the splits and tabs, restored when the project is opened again):

| Branch | Content |
|---|---|
| `main` | The work of the user: `fn/<address>.toml` (annotations and module of a function), `fn/<address>.c` (edited code), `data/<address>.toml` (names of the globals), `modules.toml` (modules created by the user) |
| `generated` | The decompiled code the edited functions were edited on (`git diff generated main -- fn/401a20.c` shows the edits) |
| `llm/<n>` | A proposal of the LLM waiting for a review (merged into main when accepted and saved) |

Only the annotated and edited functions are in the repository, its size follows the work, not the size of the binary.
Fat binaries keep each program under `p<index>/`.

### TUI

Viewers:
  - :heavy_check_mark: Headers
  - :heavy_check_mark: PE Sections
  - :heavy_check_mark: ELF Sections
  - :heavy_check_mark: Mach-O Sections
  - :heavy_check_mark: Hex Viewer
  - :heavy_check_mark: Disasm Viewer (linear, with function labels and annotations; sections are decoded around the cursor, from the instruction starts known by the analysis, whatever their size)
  - :heavy_check_mark: Control flow graph viewer (radare2-like node graph), with the disassembly or the C code in the nodes
  - :heavy_check_mark: Call graph viewer, with the summary, the disassembly or the C code of the functions in the nodes
  - :heavy_check_mark: Functions, strings, imports, modules and memory map tables
  - :heavy_check_mark: C code of the modules (every function of a module, synchronized with the addresses, editable)
  - :heavy_check_mark: Review of the LLM proposals
  - :heavy_check_mark: Shared libraries: listed in the explorer, loaded on demand (analysis, decompilation and project of their own, in
    `libs/<library>` of the project), an imported function opens in the library that exports it (loaded first when
    needed), the libraries loaded are restored with the session
  - :heavy_check_mark: C syntax highlighting, comments included (`//` and `/* */` over several lines)

The analysis runs in the background when the TUI starts, then the project opens (modules, cache) and every function is
decompiled. The title bar shows the stage, the progress of the decompilation (bar, percentage, remaining time) and `[+]`
when there are unsaved changes.

The content area is split as in vim: each split is a group of tabs, each tab shows a view and has its own jumplist.
Anything can be opened in any split (graphs, C code, disassembly, tables...). Two splits can be linked (`Ctrl-w b`): the
cursor of one moves the other, for instance the C code of a module next to the control flow graph of the function under
the cursor.

Key bindings (vim-like, the main ones can be changed in the `[keys]` section of `~/.execdumprc`):

| Keys | Action |
|---|---|
| `Tab` | Switch between the explorer and the content |
| `e` | Show/hide the explorer |
| `Enter` / `t` / `s` / `v` | Explorer: open in the current tab / a new tab / a split below / a split on the right |
| `:` | Command line (see the commands below) |
| `/` | Search: filters the tables, finds the next matching node or line |
| `Ctrl-o` / `Backspace` | Go back to the previous view of the tab |
| `Ctrl-r` (or `Ctrl-i` when the terminal can tell it apart from `Tab`) | Go forward |
| `?` | Help |
| `q` | Quit (refused when there are unsaved changes: `:w` saves them, `:qa!` quits without saving) |

Splits and tabs:

| Keys | Action |
|---|---|
| `Ctrl-w s` / `Ctrl-w v` | Split below / on the right (the new split shows the same view) |
| `Ctrl-w h` `j` `k` `l` (or the arrows) | Go to the split on the left / below / above / on the right (on the left of the leftmost split: the explorer) |
| `Ctrl-w w` / `Ctrl-w W` / `Ctrl-w p` | Next / previous / last visited split |
| `Ctrl-w H` `J` `K` `L` | Move the tab to the split in that direction (a new split when there is none) |
| `Ctrl-w q` / `Ctrl-w o` | Close the split / close the other splits |
| `Ctrl-w =` / `Ctrl-w <` `>` `-` `+` | Equal sizes / resize (a count before `Ctrl-w` multiplies the step) |
| `Ctrl-w t` | Same view in a new tab |
| `Ctrl-w b` | Link (or unlink) the split with the previous one |
| `gt` / `gT` / `{n}gt` | Next / previous / nth tab of the split |

In the graphs:

| Keys | Action |
|---|---|
| `h` `j` `k` `l` | Scroll by one cell (`H` `J` `K` `L` scroll faster, `Ctrl-d` / `Ctrl-u` by half a page) |
| `n` / `p` | Next / previous node (top to bottom, left to right) |
| `gg` / `G` | First / last node |
| `t` / `f` | Follow the true / false branch of the selected block |
| `c` | Center on the selected node |
| `v` / `V` | Change what the selected node / every node shows: disassembly or C code (blocks), summary, disassembly or C code (functions of a call graph) |
| `Enter` | Go to a function called from the selected block / open the selected function of the call graph |
| `Space` | Switch between the graph and the linear disassembly of the function |
| `x` | Cross references to the function |
| `C` | Call graph from the function |
| `D` | C code of the module of the function, on the line of the selected block |
| `+` / `-` / `i` / `r` | Call graph depth / show imports / re-root at the selected function |
| `U` | Call graph: go up to the parent graph (re-root at a caller of the root, picked in a popup when there are several) |

Edges colors: green for a taken conditional branch (`t`), red for a conditional branch not taken (`f`), blue for unconditional jumps, grey for fall-through, purple for jump table entries. In the call graph, dashed edges are tail calls (purple) and functions referenced by address (grey).

In the C code (a module, every function of it one after the other; functions not decompiled yet show a placeholder
until their code arrives). The gutter shows the address of each line, `~` marks the edited functions, `!` the conflict
markers and `·` the functions being decompiled again:

| Keys | Action |
|---|---|
| `h` `j` `k` `l`, `w` / `b`, `0` / `^` / `$` | Move the cursor (`J` `K` by more lines, `Ctrl-d` / `Ctrl-u` by half a page, counts work: `10j`) |
| `gg` / `G` / `{n}G` | First / last / nth line of the module |
| `n` / `p`, `]f` / `[f` | Next / previous function |
| `Enter` / `gd` | Go to the function (or the global) under the cursor |
| `Space` / `D` | Control flow graph of the function, on the block of the line |
| `i` `a` `A` `I` `o` `O` | Insert mode (arrows, `Enter`, `Backspace`, `Delete`, `Tab`), `Esc` goes back to the normal mode |
| `dd` | Delete the line |
| `u` / `U` | Undo / redo |
| `cn` | Rename the variable, function or global under the cursor (`:rename`) |
| `ct` | Retype the variable under the cursor (`:retype`) |
| `cs` | Give a prototype to the function (`:sig`, prefilled with its current one) |
| `;` | Comment above the line |
| `M` | Move the function to a module (`:mv`) |
| `]c` / `[c` | Next / previous conflict between the edits and the decompiled code |
| `x` / `C` | Cross references / call graph of the function |
| `L` | Ask the LLM to improve the function: its proposal shows in `:review` |

In the review of the LLM proposals: `j` / `k` move, `n` / `p` go to the next / previous proposal, `a` accepts it, `r`
rejects it, `Enter` opens the code of its function. Accepted proposals are merged into `main` on the next `:w`.

Commands:

| Command | Action |
|---|---|
| `:0x401000`, `:main` | Go to an address, a function or a symbol |
| `:c [function]` | C code of the module of a function |
| `:source <module>` | C code of a module |
| `:callgraph [function]`, `:depth <n>`, `:up` | Call graph from a function (or the entry point), its depth, its parent |
| `:functions`, `:strings`, `:imports`, `:modules`, `:sections` | Tables |
| `:entry` | Graph of the entry point |
| `:sp [function]`, `:vs [function]` | Split below / on the right, on a function |
| `:tabnew [function]`, `:tabclose`, `:tabnext`, `:tabprevious`, `:only` | Tabs and splits |
| `:link`, `:unlink` | Link the split with the previous one (their cursors follow each other) |
| `:rename <name> <new>` | Rename a variable of the current function, a function or a global (`-` restores the original name) |
| `:retype <variable> <C type>` | Retype a variable (same size only: the code stays correct, `-` restores it) |
| `:sig <prototype>` | Give a prototype to the current function: `int parse(const char *text, size_t size)` (its callers follow) |
| `:summary [text]` | Summary of the function (a comment at the top of its code) |
| `:comment <text>` | Comment above the line |
| `:mv <module> [function]`, `:mkmod <module>`, `:rmmod <module>`, `:renmod <old> <new>` | Organize the modules (paths such as `net/socket.c`) |
| `:revert` | Drop the edits of the current function |
| `:ours`, `:theirs`, `:both` | Resolve the conflict under the cursor: keep the edited code, the decompiled code, or both |
| `:llm`, `:llm modules [module\|all]` | Ask the LLM to improve the current function / to organize the functions of a module (or of the program) |
| `:review`, `:accept <n>`, `:reject <n>` | Review the LLM proposals |
| `:w [directory]` | Save the project (and the session), in another directory when given |
| `:export <directory>` | Export the C code as a source tree (once everything is decompiled) |
| `:lib <name or path>` | Load a shared library (one the binary needs, or any file), with its own project |
| `:q`, `:q!` | Close the tab (the split when it was its last tab, execdump when it was the last split) |
| `:qa`, `:qa!`, `:wq` | Quit, quit without saving, save and quit |

```toml
# ~/.execdumprc
[keys]
quit = 'q'
down = 'j'
up = 'k'
left = 'h'
right = 'l'
next_node = 'n'
prev_node = 'p'
follow_true = 't'
follow_false = 'f'
detail = 'v'
```

The LLM assistance uses the `[llm]` section (any backend of the [llm](https://crates.io/crates/llm) crate):

```toml
# ~/.execdumprc
[llm]
backend = "anthropic"              # openai, anthropic, ollama, google, deepseek, mistral, groq, xai, openrouter
model = "..."
api_key_env = "ANTHROPIC_API_KEY"  # or api_key = "..."
# base_url = "http://localhost:11434"
# max_tokens = 2048
# temperature = 0.2
```

![tui](https://github.com/romainaugier/execdump/blob/main/res/tui.png)

## Acknowledgement

This tool is based on several amazing open-source projects (go check them out!) :
 - [Capstone](https://github.com/capstone-engine/capstone)
 - [Ratatui](https://ratatui.rs/)
 - [LLVM](https://llvm.org/)
 - [libgit2](https://libgit2.org/)
