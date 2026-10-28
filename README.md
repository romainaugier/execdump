# execdump

execdump is a command-line tool that helps you analyze Windows's PE, Linux's ELF and macOS's Mach-O files (x86, x86_64 and aarch64) by parsing and printing the required information about them, or navigate through them using a terminal-based ui.

This project is currently a work in progress so not everything is supported, and it might be broken.

The goal is to provide a fast, reliable and cross-platform reverse-engineering application.

execdump might evolve into a library later, instead of just being a standalone command-line tool.

## Building

The decompiler lifts the code to LLVM IR and links LLVM 18 statically: building needs the LLVM 18 development libraries (`llvm-config` and the static libraries), found through `LLVM_SYS_181_PREFIX` or the `PATH`.

- Debian/Ubuntu: `apt install llvm-18-dev libpolly-18-dev libzstd-dev zlib1g-dev`
- macOS: `brew install llvm@18 zstd`, then `export LLVM_SYS_181_PREFIX=$(brew --prefix llvm@18)`
- Windows: build it with `get_llvm.sh` (see below) from Git Bash started in a VS developer environment (`vcvarsall x64` or `vcvarsall arm64`), with `cmake` and `ninja` on the `PATH`. No prebuilt package links: [llvm-package-windows](https://github.com/vovkos/llvm-package-windows) has no AArch64 backend and no arm64 build, and the official release asks for a `libxml2s.lib` it does not ship

If you don't want to use a package manager and instead install only what is needed, you can use the `get_llvm.sh` script, and then set `LLVM_SYS_181_PREFIX` to `third_party/llvm/<os>-<arch>` (where the necessary llvm components have been installed). Linux and macOS arm64 use the release tarballs, macOS x86_64 and Windows are built from source with the X86 and AArch64 backends only.

The CI builds the Windows LLVM once per target with `get_llvm.sh` and keeps it in the Actions cache (`.github/actions/llvm-windows`), keyed on the target and `get_llvm.sh`: changing the script rebuilds it (about an hour on the runners).

```
cargo build --release
```

The time spent in each stage of a project (analysis, background decompilation, cache, modules, export) on a binary:

```
cargo run --release -p execdump-project --example profile -- /usr/bin/python3 [workers] [max seconds of decompilation]
```

Every function of some binaries decompiled with overflow checks, the panics grouped by where they happen (`SWEEP_TRACE=1` prints each function before it is decompiled, `SWEEP_WORKERS` sets the number of threads and `SWEEP_STACK` their stack size, a small one finds the deepest recursions):

```
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    cargo run --release --target-dir target/checked -p execdump-project --example sweep -- /usr/bin/*
```

The sweep also measures the C code of each binary: its lines, the copies between variables (`v1 = v2;`), the `goto`s, the memory accesses through a cast pointer (`*(int *)((char *)p + 8)`), the local variables and the instructions kept as inline assembly. With `SWEEP_COMPILE=1` it checks which functions compile (`SWEEP_CC` sets the compiler, `cc` by default): every function goes in one translation unit after the types of the type database and the prototypes it uses, its globals declared with the type it accesses them with. `SWEEP_REPORT=file.tsv` saves the counts of every function, `SWEEP_BASELINE=file.tsv` compares a run with a saved one, the totals and the functions that got worse:

```
SWEEP_COMPILE=1 SWEEP_REPORT=before.tsv cargo run --release -p execdump-project --example sweep -- /usr/bin/tar
# change the decompiler
SWEEP_COMPILE=1 SWEEP_BASELINE=before.tsv cargo run --release -p execdump-project --example sweep -- /usr/bin/tar
```

`SWEEP_TEXT=file.c` writes the C code of every function, by binary and address: two runs compared with `diff` show every change of the output, not only the counts.

A function whose decompilation panics shows the panic as its error (`decompilation failed: panicked at ...`), the other functions are not affected. A crash of execdump itself gives the terminal back before printing the error, the fatal errors that are not panics (stack overflows, invalid memory accesses) included on Unix. The analysis and the decompiler run on threads with large stacks (512 MB reserved, only what is used is allocated): debug builds recurse deeply on big functions, and are much slower, `--release` is the way to explore large binaries.

Errors are `anyhow::Error` across the crates: a failure carries what was being done when it happened (`cannot parse a.out: Unexpected end of file`), the status line and the messages show the whole chain on one line. The typed errors that callers match on stay typed (`ReaderError` of the binary readers) and convert with `?`.

## Usage

```
Usage: execdump.exe [OPTIONS] [FILE_PATH]

Arguments:
  [FILE_PATH]

Options:
  -t, --tui
          Opens the executable in the terminal-based user interface for exploration
      --specs
          Prints the build, machine and platform specs to paste in bug reports, then exits

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
      --pe-delay-imports
          Dump the delay load imports (their DLLs, functions and slots), if any
      --pe-tls
          Dump the TLS Directory and its callbacks, if any
      --pe-load-config
          Dump the Load Configuration (security cookie, Control Flow Guard functions), if any

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
      --macho-fixups
          Dumps the pointers dyld writes of each architecture (chained fixups, binds), if any
      --macho-exports
          Dumps the Mach-O exported symbols of each architecture (exports trie), if any

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
          callgraph (call graph as Graphviz dot), llvm (optimized LLVM IR), c (decompiled C code),
          storage (where the variables are while the functions run)
          [possible values: functions, cfg, callgraph, llvm, c, storage]
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
- :heavy_check_mark: TLS Table: its callbacks are functions that run before the entry point (`tls_callback_0`)
- :heavy_check_mark: Load Config Table: the Control Flow Guard functions table (every function called through a
  pointer) and the SEH handlers of 32-bit code are function starts, the security cookie and the guard check and
  dispatch pointers are named. A call checked by Control Flow Guard is the call of its target in the C code (the
  check is left out, the call through `__guard_dispatch_icall_fptr` calls the pointer in `rax`)
- :x: Bound Import Table
- :x: Import Address Table
- :heavy_check_mark: Delay Import Descriptor: the functions of a DLL loaded at their first call are imports (their
  slots), the thunks the slots hold until then are named (`__imp_load_<function>`)
- :x: CLR Runtime Header

Code:

- :heavy_check_mark: Basic disassembly of the code sections

### ELF

Headers:

- :heavy_check_mark: ELF Header
- :heavy_check_mark: Program Headers (and interpreter)
- :heavy_check_mark: Section Headers. When no section has the flag of code (hand written headers, the nasm binaries of
  crackmes), the code is in the executable segments: the section of the entry point and the ones named as code

Sections:

- :heavy_check_mark: Symbol Tables (.symtab, .dynsym)
- :heavy_check_mark: Dynamic Section
- :heavy_check_mark: Relocations (.rel, .rela), the pointers the loader writes applied to the memory map of the program (the relative ones of a PIE, the GOT slots of the functions it defines)
- :heavy_check_mark: Imports (needed libraries and imported symbols)
- :heavy_check_mark: Notes (build-id, ABI tag, GNU properties)
- :x: Symbol Versioning (.gnu.version, .gnu.version_r)
- :heavy_check_mark: DWARF debug information (DWARF 2 to 5, compressed sections included): the names and the source
  files of the functions and the globals, and for C and C++ the types (structs, unions, enums, typedefs, as the
  debug information lays them out) and the prototypes of the functions with the names of their parameters. The
  object files (their debug sections need relocations) and the separate debug files are not read yet

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
- :heavy_check_mark: Chained fixups (`DYLD_CHAINED_PTR_64`, `_64_OFFSET`, `_32`, the arm64e ones): the rebases are
  written in the memory map of the program (on disk a pointer is a link of its chain), the binds are import slots
- :heavy_check_mark: Bind opcodes of Dyld Info (binds and lazy binds: the imports referenced from data), the rebases are
  already the pointers on disk
- :heavy_check_mark: Exports trie: the exported symbols name the functions of stripped binaries
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
  - :heavy_check_mark: Type database parsed from C headers: prototypes, typedefs, structs (with layouts), unions and enums, bundled for glibc and Win32 (mingw-w64). The glibc one has gettext, error, obstack, argp, fts, mntent, statfs, xattr, uchar and the fortified functions compilers call (`__memcpy_chk`...). Each language adds a database of its runtime to the programs that have its code (`data/typedb/go.h`: the strings, slices, interfaces, itabs and types of Go, the allocations, conversions, channels and maps of the runtime, `fmt`, `strings`, `strconv`...; `data/typedb/rust.h`: `&str`, the allocator, the panics). A C or C++ program with debug information adds its own types to it, and its functions get the prototypes it describes (the names of their parameters included); a pointer the function returns is the struct of its prototype
  - :heavy_check_mark: The Linux system calls by their name (`syscall(SYS_write, 1, "text", 4)`, x86_64, x86 and aarch64), the
    paths they take as strings, the buffers written with their length (the strings of assembly are not NUL terminated).
    `exit` and `exit_group` end the code: the function that follows them in the binary is not part of it
  - :heavy_check_mark: The calls whose signature is not known (through a pointer) return a `double` when the code reads the floating point result register after them and not the integer one

Analysis:
  - :heavy_check_mark: Format-agnostic program model (memory map, symbols, imports, entry point)
  - :heavy_check_mark: Function discovery by recursive descent, seeded by the entry point, symbols, exports, PE exception table (.pdata), Mach-O LC_FUNCTION_STARTS, ELF .eh_frame and init arrays, the Go pclntab, then call targets and code references (works on stripped binaries)
  - :heavy_check_mark: Control flow graphs (true/false branches, tail calls, x86 jump tables)
  - :heavy_check_mark: Functions split by the compiler (hot and cold parts): the jumps between the parts do not create
    functions in the middle of others, the code reached only from a cold part is a fragment that stops at the code
    already recovered (no copies of the rest of the function)
  - :heavy_check_mark: Noreturn functions (known names and propagation, the Rust panics of `core::panicking` and the
    ones of `std::panicking` that panic, not `set_hook`)
  - :heavy_check_mark: Imports resolution through PLT entries, Mach-O stubs, IAT thunks and indirect calls (aarch64 adrp/ldr tracking),
    and the PLT of the position independent code of x86, which jumps through the global offset table ebx holds (`jmp [ebx+0xc]`)
  - :heavy_check_mark: Call graph and cross references
  - :heavy_check_mark: Strings (ASCII and UTF-8, UTF-16 for PE) and references annotations
  - :heavy_check_mark: aarch64 jump tables: the instructions before the jump run for every index its bound check
    allows (the copies of the compared register are the index), so the patterns of the compilers are all read the
    same way: entries of a byte or two added to a label of the function (clang, gcc, MSVC), absolute entries (Go)
  - :heavy_check_mark: The data PE linkers put in the sections of code (import tables, debug directory, CLR header and
    metadata) is not taken for code when an instruction refers to it
  - :x: .NET assemblies: recognised (their CLR header), their code is CIL bytecode and is not decompiled yet (the only
    machine code is the stub that jumps to `_CorExeMain`)
  - :heavy_check_mark: Rust fat pointers for strings: a Rust binary (its symbols, or the paths of the standard library its
    panics keep when it is stripped) has strings that are a pointer and a length, laid out one after the other without NUL.
    The (pointer, length) pairs of the data (tables of `&str`, panic locations) are strings of their own in the strings
    table, and the decompiler cuts a string at its length when the function passes it to a call with its length, stores
    both next to each other (the fields of a `&str`), returns them in a pair of registers, or returns the pointer and
    writes the length to its first result pointer (Go): `write_all(out, "world", 5)`
    instead of `write_all(out, "worldsuccesswarning: low disk space...", 5)`, `return "unknown" | ((__int128)7 << 64);`
  - :heavy_check_mark: Languages (`crates/execdump-decompiler/src/lang`): what the decompiler knows of each language other
    than C is a module of its own behind one trait, with a hook per stage (the functions that do not return, the calling
    convention and the signatures of the runtime, the calls the lifter turns into operations of its own, the idioms in
    the C, the modules of the functions, where the debugger stops first and which calls a step goes over). The built-in
    languages are Go, Rust, C++ (its demangled prototypes, the classes they name, its exceptions, the modules of its
    namespaces) and C, the default of every hook. A language has a type database of its runtime, its prototypes are
    the ones of the C names of its functions (`runtime_makeslice` of `runtime.makeslice`) and become signatures with
    its calling convention, checked against what the binary says of the function (the size of the arguments of the
    pclntab: a prototype of another version of the runtime is not used), its parameters name the variables passed to
    them: `const char *str = main_level(v1, &v4); int64_t len = v4; int64_t val = main_add(v1, 4); void *v9 =
    runtime_convTstring(str, len); void *v10 = runtime_convT64(val);`. Each function belongs to a language, with its hooks and its calling
    convention: the functions of the pclntab of a Go program are Go, the other ones are C (the C code of cgo has the
    calling convention of the platform: `_cgo_try_pthread_create(pthread_t *newthread, const pthread_attr_t *attr,
    ...)` retries `pthread_create` in a loop instead of reading the registers of Go). The bytecode languages (.NET,
    Java) will be front ends of their own
  - :heavy_check_mark: Go binaries (PE, ELF and Mach-O, x86_64 and aarch64, stripped or not): the pclntab the Go runtime
    keeps (found by its section, else by its header in the data; layouts of Go 1.2 to 1.15, 1.16/1.17 and 1.18 and
    later) names every function, gives its bounds and its source file. The functions are in modules by package and
    file (`runtime/proc.go`, `main/main.go`). The decompiler uses the calling convention of the version: the register
    ABI of Go 1.17 on x86_64 and 1.18 on aarch64 (arguments and results in rax, rbx, rcx, rdi... or x0 to x15, the
    goroutine in r14 or x28 is `runtime_g`, xmm15 holds zero), the stack ABI before (and on x86, and for the assembly of the runtime:
    arguments then results in the slots above the return address, every register clobbered by calls). A function
    returns its first result, the next ones are written through pointers after its parameters, its callers pass the
    address of variables of their own: `n = fmt_Fprint(w, v, a, len, &v1, &v2)`, `*a2 = 5; return "quiet";`. The
    results kept are the ones the callers read (the pclntab bounds them with the size of the arguments and results of
    each function in the stack ABI, the size of the spill slots of the parameters in the register ABI: `main.main`, the
    `init` functions of the packages and the functions without parameters called only through function values have
    none). The calls to unknown functions (methods of interfaces, closures) pass the
    stack slots written before them and return the ones read after them (in the stack ABI), the registers read after
    them (in the register ABI). The assembly helpers of the runtime that take registers in the stack ABI
    (`runtime.cmpbody`) get them as parameters. The growth of the stack (`cmp rsp, [r14+0x10]; jbe` to
    `runtime.morestack`) is left out, the panics and fatal errors of the runtime do not return, the write barriers
    return their buffer in r11 (x25) and go from the C (`if (runtime_writeBarrier == 0) { p->f0 = v; } else {
    runtime_writebarrierptr(&p->f0, v); }` is `p->f0 = v;`). The calls into `runtime.duffzero` and `runtime.duffcopy`
    are `memset` and `memcpy` of the bytes left before their return, `runtime.deferproc` of Go 1.9 returns in rax and
    takes the arguments of the deferred function after its own (`runtime_deferproc(8, &f, &err)`). Go strings are a
    pointer and a length like the Rust ones. The type descriptors are named after their type (the module data of the
    runtime bounds them, each names its type: `&type_slice_uint8` for `[]uint8`, `&type_ptr_main_T` for `*main.T`),
    the itabs after their interface and type in the stripped binaries too (`&go_itab__os_File_io_Writer`), and the
    allocations of the runtime return a pointer to the type of their descriptor: `struct go_slice *v22 =
    runtime_newobject(&type_slice_uint8); ... v3->len`. `main.main` and the `init` functions of the packages have no
    parameters.

Decompiler:
  - :heavy_check_mark: CFG recovery
  - :heavy_check_mark: Lifting to LLVM IR (x86, x86_64, aarch64), with lazy flags and a statically tracked stack frame
  - :heavy_check_mark: SSA construction while lifting: the registers and the flags are SSA values from the start (Braun et
    al., the phis whose operands are one value are that value), only the stack frame is left to SROA, then
    data-flow cleanups (LLVM passes)
  - :heavy_check_mark: Names of the functions with a mangled symbol (C++, Rust legacy and v0): their demangled path joined
    with underscores (`std::vector<int>::push_back` is `std_vector_int_push_back`, `core::fmt::Arguments::new_v1`
    is `core_fmt_Arguments_new_v1`, `<alloc::string::String as core::ops::deref::Deref>::deref` is
    `alloc_string_String_as_core_ops_deref_Deref_deref`), the names several functions share (the instances of a
    generic, overloads) end with their address (`core_ptr_drop_in_place_17cf0`)
  - :heavy_check_mark: Signature recovery (C headers, demangled C++ symbols, then used argument registers and their widths).
    After a call the registers the callee does not preserve hold nothing known, so a register the function received
    is not passed through it: what the callee may write is found from its instructions and its callees (compilers
    keep values in the other registers across calls to the functions they know, gcc's `-fipa-ra`), the imports
    and the indirect calls may write any. A call whose arguments are guessed passes the registers written on every
    path to it, and a register only left as it was on some paths to a return is not a parameter. A parameter
    reaching the return register is the result (`return p + 1;`, `mov rax, rdi`), except a return register
    received and left as it is (`xmm0` on x86_64, `x0` on aarch64). A result twice as wide as a register is
    returned in two (`rdx:rax`, `edx:eax`, `x1:x0`: the 16 bytes structs of C, `long long` on x86, the `u128`,
    `&str` and `Option<u32>` of Rust) when a caller reads the high half after the call, it is an `__int128` whose
    halves the callers take (`(int)v`, `(const char *)(v >> 64)`). A register used
    as an address (after adding constants to it, or joined with others that are) is a pointer, and so is a result
    that is always one (a pointer, such a parameter, an offset from them, or null), what they point to comes from
    the accesses of the function. A function whose address is passed to a parameter of a known function that is
    a pointer to a function (`qsort`, `bsearch`, `signal`, `atexit`, `pthread_create`, `__libc_start_main`...)
    has the prototype of that parameter (`int compare(const void *a1, const void *a2)`), the address is the
    constant the instruction that last writes the register of the argument before the call computes (the
    arguments passed on the stack are not followed). A global holding one function (every instruction of the
    program writing it writes the address of that function, and its address is never taken) is called as that
    function, with its arguments: `static void (*check)(...); check = verify; check(a, b);` gives
    `verify(a, b)` (x86 and x86_64), and so is a global no instruction writes holding a function from the start
    (the GOT slot the loader fills for a call to a function of the binary: Rust calls the functions of the other
    crates through them, `call [rip + slot]` is `std_io_stdio__print(&args)`). `main` has its standard prototype (`int main(int argc, char **argv)`, as many
    parameters as it reads), the functions the C runtime links in (`__libc_csu_init`, `frame_dummy`,
    `__do_global_dtors_aux`...) return nothing. A result is not read by a caller that clears the register
    (`xor eax, eax`), nor by one that only returns it to callers that do not read it (followed up the call graph),
    and a function returning nothing does not end with `return;` (nor its last branches). A function returning only
    0, 1 and tests (a bit of a value too: `(flags >> 2) & 1`) returns a `bool` (`return true;`), its callers test it
    as one (`if (!named(n))`). The format string of a variadic call passed on the stack is found through the
    register it was computed in (`lea ecx, [fmt]; mov [esp], ecx`), so `printf` gets its extra arguments. A
    function is lifted once when its signature is discovered for its own C code: its discovery (every argument
    register a parameter, the low halves of the 64-bit ones apart, the return registers stored to sinks, with the
    notes of the storage), once optimized, becomes the function of the signature found (the parameters converted
    to the registers they were received in, the values reaching the sinks returned where they are computed), and
    the passes that run again have little left to do. The functions calling themselves, and the ones keeping
    registers outside of the convention, are lifted again
  - :heavy_check_mark: Control-flow structuring (if/else, loops, switches with jump tables, short-circuit conditions, tail duplication of the returns).
    The branches join where their paths meet, the paths that return early left out; a loop whose exits all
    return is left from the block of its innermost loop the most paths reach, so the branches before it still
    join there. A switch of one or two values is tests of them (`if (v == -1) break;`, a break in a case would
    leave the switch, not the loop). A loop leaves to where the paths from its header join when that does not
    end the function, else to its post dominator, else to its most targeted exit that is not a small tail (the
    tails are repeated where they are reached: `return v;` inside the loop).
    Once the copies are gone the loops get their shape: the loops whose test is first or last are `while (c)` and
    `do { } while (c)` (also when the test leaves from its else: `if (c) { x } else { break; }`), a loop that
    counts a variable initialized before it is a `for` (its initialization and its step found among the copies
    before the loop and at the end of its body, in whatever order they come, when they can move past the others),
    with an empty condition when it is left from its body
    (`for (i = 0;; i++)`, a pointer walking a list or a buffer is `p`: `for (p = head; p != 0; p = *p)`), and a
    loop tested before it is entered and after each iteration is a `while` (`if (c) { do { } while (c); }`). The
    counted loops compilers rotate are `for` loops again: `if (a < n) { i = a; do { ...; i++; } while (i != n); }` is
    `for (i = a; i < n; i++)` (with a step of one, `<` and `!=` leave at the same value), and so is a `do` loop whose
    test holds for the first value (`for (p = &table; p != &table_end; p += 24)`). The next value of a loop variable
    computed in a variable of its own (`t = i + 8; a[i] = 0; if (t >= n) break; i = t;`) is the variable stepped where
    it is first needed (`a[i] = 0; i += 8; if (i >= n) break;`). The branches that jump away go first (`if (!c) { break; } x`), and the shorter of
    two exits ending a list goes first (`if (!c) { return 0; } long; return 1;`, not in the blocks with labels,
    their declarations would move out of them). An if left with an empty branch is turned
    around (`if (!c) { x }`), and goes away when both are empty. The statements both branches of an if end
    with follow it (and the jump an if ends with when it is the one after it), an if whose body is an if
    without else is one with both conditions (`if (a && b)`). The conditions known where a statement runs (after
    `if (!c) break;` c is true, in the branches of a test its condition is true or false) make the tests of the same
    conditions on variables go: LLVM joins the paths after a test and tests again where they split. The tests that
    follow each other with a first condition in common are one: `if (a) { x } if (a && b) { y }` is
    `if (a) { x if (b) { y } }`
  - :heavy_check_mark: Switches split by the compilers are one switch again: the tests of the same value that follow
    each other (a range check before a jump table, the sparse values tested before it, the search trees of
    comparisons LLVM makes) are taken for every value of interest (the boundaries of the comparisons, the cases,
    every value of the small ranges between them), the values that lead to the same place are one case. The cases
    with the same body are grouped, the ones that do what the default does are left to it, and runs of values are
    GNU case ranges (`case 72 ... 137:`)
  - :heavy_check_mark: Expression recovery (out of SSA, divisions by constants, struct fields from the type database)
  - :heavy_check_mark: Type recovery (pointers and their pointees, signedness, prototypes). The values joined by
    phis share one pointer type (the one the most uses have), so they can be one variable. A pointer to unknown
    data points to the type of the first field accessed at a constant offset from it, a pointer written through is
    not const (a const comes from the prototype of a function it is passed to), a pointer used in an integer
    operation is converted to an integer, and a global accessed as a pointer and as an integer of that size is a
    pointer. In a byte access at the sum of two integers, the one that is not an index (extended from a narrower
    integer, scaled, a counter, a `size_t`...) is the pointer: `s[i]`, not `((char *)i)[s]`. The variadic arguments of a printf format string are typed by their conversion (`%s` a string, `%p` a
    pointer), and a pointer to anything becomes a pointer to what it is used as (`void **` to `const char **`)
  - :heavy_check_mark: Structs from the access patterns: the offsets, sizes and types accessed through a pointer
    (and the pointers joined with it by phis, or loaded from the same place of a global) make a struct when they
    are not the elements of an array (one size at its multiples, one type: the pointers to the same data, const or
    not, or to anything are one, so `argv` stays `char **`), so `p->f18` replaces `*(int64_t *)((char *)p + 24)`. A field has the type of
    the values read and written there (a pointer to a struct, to something else, a number, then `void *`), the
    bytes never accessed are padding, and an address passed to a function whose prototype says what it points to
    is a field of that type (a `struct stat` at 0x58 passed to `fstat`, then read as `p->f58.st_size`). A wide
    access over narrower ones (a copy of two fields at once) does not hide them. The structs of the same layout in a
    function are one (the levels of a tree walked by unrolled code), they are named after the function
    (`struct st_1aa40_0`) and printed before it. A struct goes from a function to its callers: the callees are
    decompiled first (the functions calling each other aside, what each saw would depend on the one decompiled
    first), a caller passing a pointer to a callee that recovered a struct for it uses that struct when its fields
    cover the caller's accesses, otherwise the caller's struct has the fields of its callees' and its own, and its
    own callers use that one; the callers take the booleans and the structs the callees return too. The other
    types a callee guessed from its uses stay its own. A source tree has the structs in `include/structs.h`. The low
    bytes of an integer field read are a conversion (`(char)p->flags`), not an access through a cast pointer. A buffer of the stack frame accessed at constant offsets is a struct
    of its size (`v20.f8`), accessed whole only it is a variable of that type (`char *endptr`, not
    `*(char **)&endptr[0]`). Passed as a struct of the type database and accessed inside it only, it is a variable
    of that struct even when the frame gives it more bytes (`struct timespec v1; v1.tv_nsec = 5; nanosleep(&v1,
    NULL);`), accessed in its elements an array of it (`struct go_eface a[2]; a[1].type = &type_int;`). A pointer to
    a struct of the type database stored once in the frame is that pointer when it is loaded back
  - :heavy_check_mark: Variable recovery (names from their use). The phis are variables assigned on the edges that lead
    to them: a phi and the variables flowing into it that are never alive at the same time (liveness on the
    variables, an inlined expression is read where the statement it is part of is, a phi reads its values at the
    end of the blocks they come from) share one variable, so the copies between them disappear (a parameter keeps
    its variable). The computations without effect are moved down to their first use in their block first, a value
    computed early being alive with the ones it is computed from (the values of loads stay next to them)
  - :heavy_check_mark: Declarations in the narrowest block: a local variable is declared at the start of the
    narrowest block that holds all its uses, when entering it always writes the variable before reading it (a
    value carried from one iteration to the next stays declared around the loop; blocks with labels are left
    out), and at its first assignment when that is a statement of the block that does
    not read it (`int fd = open(file, 66);`). A case of a switch that declares variables is a block (`case 3: {`)
  - :heavy_check_mark: Differential test of the C backend: random programs with branches and loops are built as LLVM
    IR, optimized like the lifted code, decompiled, and the C is run by an interpreter, it must return what the
    programs return
  - :heavy_check_mark: Jumps through a register holding a constant (`lea eax, [a]; inc eax; jmp eax`) are followed: code
    hidden on purpose after the first byte of what reads as another instruction is decompiled
  - :heavy_check_mark: Stack frame variables: when the address of a part of the frame is taken (buffers passed to calls,
    pointers kept in locals, typical of 32-bit and unoptimized code), the frame is split by how it is accessed: each
    escaping address starts a buffer that extends to the next one, to the registers the prologue saves or to the
    return address (what it points to stays reachable from it, so the code stays correct, the arguments are above
    the return address), the scalars below the buffers become values. A buffer given with its size to a known function (`fgets(buf, 9, f)`,
    `read`, `memset`, `snprintf`...) ends there, so does a buffer given to a function of a runtime known to access a
    number of bytes from it (the 32-byte `tmpBuf` of `runtime.stringtoslicebyte` and the other conversions and
    concatenations of strings of Go: the variables after it become values), the address of the arguments a realigned
    frame keeps is not part of it. The address of a variable of the frame is a constant: it is not a variable of its
    own, the accesses through it are accesses to the variable (`v6.f1 = v5;`, not `int64_t *v10 = &v6.f1; *v10 =
    v5;`). A buffer that only escaped through a store
    the split made dead is split once optimized (gcc's realigned frame of `main` keeps the address of the arguments
    with the saved registers: they are `argc` and `argv` again). The addresses computed from a copy of the
    stack pointer (`mov rdi, rsp`) are addresses in the frame too. Strings written on the stack by stores of
    constants (`mov dword [ebp-0x25], 0x4763305f`..., also overlapping ones: `"secr"` at 0 then `"ret\0"` at 3)
    are one `memcpy` of the string literal, and `rep stos` of a repeated byte is a `memset`
  - :heavy_check_mark: Trivial functions inlined: a function whose body is one statement with no effect of its own
    (`abort();`, often a cold part the compiler split off or a noreturn stub, `return f(a1, a2);`, `return 42;`,
    `return &g;`) is shown by its callers instead of the call, with the arguments in place of the parameters
    (`abort(); // fatal`: the name of the function is a comment when it has one, a symbol or a name given by the
    user). It is found when the function is decompiled (the small ones only are looked at), callees first, so the
    chains of them are followed, and it is printed on one line (`void fatal(void) { abort(); }`). A tail call to
    a function that does not return ends the path, and on x86 the arguments a tail call passes on the stack are
    the ones the function received
  - :heavy_check_mark: Stack protector removed: the canary is recognized by its value (`fs:0x28` on x86_64, `gs:0x14`
    on x86, `__stack_chk_guard`, the MSVC `__security_cookie`), its checks always pass (the branches to
    `__stack_chk_fail` and the calls to `__security_check_cookie` disappear, with the duplicated checks before
    each return), its stores are removed and its slot ends the buffers below it (`char buffer[64]`, not the rest
    of the frame)
  - :heavy_check_mark: 32-bit calls: the stack arguments by size (doubles and 64-bit integers take two slots), the
    arguments of variadic functions from their format string, the pointer sized types of the headers (`size_t`...)
  - :heavy_check_mark: The values known in the registers at the start of a block (the stack pointer, the constants
    addresses are computed from) are the ones every path to the block agrees on: a counter set before a loop changes
    in it, `mov al, [key + ecx - 1]` is an access to the array, not to one of its bytes
  - :heavy_check_mark: Position independent code of x86: `call __x86.get_pc_thunk.bx` (a function that only reads its
    return address) gives ebx the address after the call, so the accesses through the global offset table are the
    globals of the program. A stripped `__stack_chk_fail_local` still fails the stack protector: a check whose
    failing branch calls a function that does not return is removed like the others
  - :heavy_check_mark: Registers outside of the calling convention, on x86: hand written assembly passes values in the
    registers it chooses (a checksum taking its bounds in eax and ebx and returning it in ecx), and gcc gives its
    local functions the convention of `regparm` (eax, edx, ecx). A register the function reads before writing it is
    a parameter, a register it changes is a result when a caller reads it after the call (`int v2 =
    sub_8048115(entry0, 0x8048123);`). The compiled code is not taken for assembly: the registers a function saves
    and restores (`push ebx` ... `pop ebx`, wherever the frame is) are neither, the bits of a register kept when
    its low byte is written (`mov al, 1`, `sete bl`) are no use of it, the stack room a compiler makes with a
    register it does not use (`push ecx`) does not read it, and the functions called from elsewhere keep the
    convention
  - :heavy_check_mark: C code generation (`--decompile c`)
  - :heavy_check_mark: Address of the statements: each machine instruction is the debug location of the LLVM instructions
    lifted from it, which the passes keep, so nearly every line of C has the address it comes from (the gutter of the C
    views, and the synchronization of the C code with the disassembly and the graph)
  - :heavy_check_mark: Storage of the variables (`--decompile storage`, kept with the C code in the cache of the
    projects, for a debugger): where each variable is while the function runs, a register or a stack slot over
    ranges of addresses. A location is one u32 (2 bits of kind, then a register: 8 bits of id, 2 of width, 2 of
    byte offset; a stack slot: a 28-bit offset from the stack pointer at the entry, and a bit for the slot of the
    stack canary; or a constant), a range 12 bytes (start and end as offsets from the start of the function, the
    location); the ranges of a variable are sorted and do not overlap, the location at an address is a binary
    search. The final lift notes the values with `llvm.dbg.value`, which the passes keep without changing the code:
    the values written to the registers and the stack slots after each instruction, and the phis of the registers
    (noted by the lifter) and of the split stack slots (debug variables, noted by mem2reg) at the start of the
    blocks (a marker gives the address of each machine block). The C backend reads the notes of the values that
    are variables (or that
    an extension, a conversion or a phi of a variable comes from), then the ranges follow the machine code: a
    location holds a variable from a note until an instruction writes it (the registers it writes, the ones a call
    clobbers, the stack slots it stores to), a block starts with what all the blocks before it agree on. The
    variables of the stack frame (buffers) are in their slot for the whole function. The offset of the stack
    pointer from its value at the entry is kept the same way (ranges of stack locations, from the stack pointer
    tracked through the instructions), so the stack slots are found from the stack pointer of a running function,
    and the shape of each variable (`i4`, `u8`, `f8`, `b`, `p`, `s` for a pointer to text, `t64` for a buffer of 64 chars,
    `x24` for 24 bytes) tells
    how to read and show its value
  - :heavy_check_mark: Strings and constants: addresses of strings are string literals (the ones passed to functions even when they end
    another string, linkers merge them), loads from constant addresses of read-only data are their value (numbers,
    floating point numbers, strings, functions), constants that are the address of a function are its name. Literals
    are exact: the UTF-8 text is its characters (`"Vérification"`), the control characters and the bytes that are not
    UTF-8 are escapes (a literal is split after an escape followed by a digit, `"\xff" "1"`). In the TUI, `gs` on a
    literal (`:string`) shows it as text, as a C literal of ASCII characters (`"V\xc3\xa9rification"`, the offsets the
    code uses), as bytes, as a shell argument (`$'...'`) and as Python bytes, `Enter` copies one (see below). Printable
    characters stored in chars are character literals
  - :heavy_check_mark: LLM improvement pass (`--llm`): names of the unnamed functions and of the variables, types and a summary, validated before being applied (callees first, their new names show in their callers)
  - :heavy_check_mark: LLM improvement in the TUI (`L` or `:llm`, a proposal to review): the names, types and summary, and the
    function rewritten as clear and documented C (structured control flow, no needless temporaries, the new names,
    comments where the code is not obvious) with the same behavior. The code the model gets has the address of each
    line in a marker at its end (`/*@4011a0*/`), its lines keep the markers of the lines they do the work of: the
    rewritten code keeps the addresses of its lines (the gutter, the breakpoints, the line the debugger is at, the
    steps by lines), markers the model made up are dropped. The proposal says how many lines have an address, and when
    the code lost the function name, a call or the balance of its braces. Accepted, the code is the function under its
    new name and replaces the decompiled one rendered with the new names and types (it is not merged into it); the
    addresses of the lines are kept with the edit (`fn/<address>.lines` next to `fn/<address>.c`) and follow its later
    edits
  - :heavy_check_mark: User annotations followed by the decompiler: names of the functions and globals, prototypes, variables

### Projects

The C code of the whole program is a project: every function is decompiled in the background, organized in modules (source files), annotated and edited, and the work is saved in a git repository next to the binary.

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
- :heavy_check_mark: LLM proposals (names, types and summary of a function with its code rewritten, organization of the functions in modules),
  reviewed as diffs before being accepted
- :heavy_check_mark: Export of the modules as a source tree: `src/<module>` and `include/<module>.h` (prototypes of the
  functions), `include/execdump.h` (`undefined` types), `include/execdump_imports.h` and `include/execdump_globals.h`.
  The tree is meant to be read and built upon, it does not always compile as it is.

The project directory (`<binary>.edproj` by default, `--project` or `:w <dir>` to choose another one) holds a bare git repository (`repo.git`) and the session (`session.toml`, the splits and tabs, restored when the project is opened again):

| Branch | Content |
|---|---|
| `main` | The work of the user: `fn/<address>.toml` (annotations and module of a function), `fn/<address>.c` (edited code), `data/<address>.toml` (names of the globals), `modules.toml` (modules created by the user) |
| `generated` | The decompiled code the edited functions were edited on (`git diff generated main -- fn/401a20.c` shows the edits) |
| `llm/<n>` | A proposal of the LLM waiting for a review (merged into main when accepted and saved) |

Only the annotated and edited functions are in the repository, its size follows the work, not the size of the binary. Fat binaries keep each program under `p<index>/`.

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
  - :heavy_check_mark: Explorer as a tree: one node per program of the binary (its analysis, modules, headers, sections and tables)
    and per loaded library, as wide as its content
  - :heavy_check_mark: Shared libraries: listed in the explorer, loaded on demand (analysis, decompilation and project of their own, in
    `libs/<library>` of the project), an imported function opens in the library that exports it (loaded first when
    needed, from the graphs, the call graphs and the C code with `gd`), the libraries loaded are restored with the session
  - :heavy_check_mark: Syntax highlighting in the colors of VS Code (Dark+ with the semantic colors of C/C++): the control
    flow purple, the other keywords blue, the names of the types teal (after `struct`, `union` and `enum`, the `_t`
    typedefs, the typedefs of the type database: `FILE`, `pthread_attr_t`), the functions yellow, the variables light
    blue, comments over several lines included. A language is a table of its keywords, types, comments and strings
    (`src/syntax.rs`): C, C++, Go and Rust, `:syntax <c|c++|go|rust>` highlights the code of a view as one of them
  - :heavy_check_mark: Debugger (gdb or lldb): the program runs under the debugger and the decompiled code is its source
    (see below)

The analysis runs in the background when the TUI starts, then the project opens (modules, cache) and every function is decompiled. The title bar shows the stage, the progress of the decompilation (bar, percentage, remaining time) and `[+]` when there are unsaved changes.

The content area is split as in vim: each split is a group of tabs, each tab shows a view and has its own jumplist. Anything can be opened in any split (graphs, C code, disassembly, tables...). Two splits can be linked (`Ctrl-w b`): the cursor of one moves the other, for instance the C code of a module next to the control flow graph of the function under the cursor.

Everything the interface does is a command: the keys are bound to commands (in the global context, the explorer, any view or one kind of view, the most specific first), and every command can be typed after `:` (`:toggle-explorer`, `:next-split`, `:depth +1`...). A command goes to the focus first (the explorer or the view of the split), then to the splits and tabs, then to the application. `?` (or `:help`) lists the keys of each context with the command they run, then the commands without a key.

The command line suggests what can be typed: the commands (with their arguments and help) while the name is typed, then the values of the argument being typed: functions (`:c`, `:cg`, `:sp`...), modules (`:source`, `:mv`), variables and functions (`:rename`, `:retype`), libraries and files (`:lib`, `:w`, `:export`), proposals (`:accept`), the words a command takes (`:open tab`, `:focus-split left`). When there is nothing to suggest, its usage and help show.

Key bindings (vim-like, the main ones can be changed in the `[keys]` section of `~/.execdumprc`):

| Keys | Action |
|---|---|
| `Tab` | Switch between the explorer and the content |
| `e` | Show/hide the explorer |
| `Enter` / `t` / `s` / `v` | Explorer: open in the current tab / a new tab / a split below / a split on the right (`Enter` on a node folds or unfolds it) |
| `h` | Explorer: fold the node, or go to the node of the item |
| `/` | Explorer: filter the items while typing (case insensitive, the folded nodes too: `/socket` keeps the modules with socket in their path), the selection on the first one; `n` / `p` go to the next / previous item found, `Enter` opens it, `Esc` shows every item again with the nodes above the selected one open |
| `<` / `>` / `=` | Explorer: narrower / wider / back to the width of its content. Content: narrower / wider split / equal sizes (without splits side by side, the explorer gives or takes the width) |
| `:` | Command line (see the commands below): suggestions while typing, `Tab` / `Shift-Tab` go through them, `Up` / `Down` through the history |
| `/` | Search: filters the tables, finds the next matching node or line. While the search is active, `n` / `p` (or `N`) go to the next / previous match, `Esc` ends it (`n` / `p` move between the nodes, labels or functions again) |
| `Ctrl-o` / `Backspace` | Go back to the previous view of the tab |
| `Ctrl-r` (or `Ctrl-i` when the terminal can tell it apart from `Tab`) | Go forward |
| `?` | Help: the keys and the commands (`j` / `k` scroll it) |
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
| `+` / `-` / `i` / `r` | Call graph depth / show imports / re-root at the selected function (`=` equalizes the splits) |
| `U` | Call graph: go up to the parent graph (re-root at a caller of the root, picked in a popup when there are several) |

 Edges colors: green for a taken conditional branch (`t`), red for a conditional branch not taken (`f`), blue for unconditional jumps, grey for fall-through, purple for jump table entries. In the call graph, dashed edges are tail calls (purple) and functions referenced by address (grey).

In the C code (a module, every function of it one after the other; functions not decompiled yet show a placeholder until their code arrives). The gutter shows the address of each line, `~` marks the edited functions, `!` the conflict markers and `·` the functions being decompiled again:

| Keys | Action |
|---|---|
| `h` `j` `k` `l`, `w` / `b`, `0` / `^` / `$` | Move the cursor (`J` `K` by more lines, `Ctrl-d` / `Ctrl-u` by half a page, counts work: `10j`) |
| `gg` / `G` / `{n}G` | First / last / nth line of the module |
| `n` / `p`, `]f` / `[f` | Next / previous function |
| `Enter` / `gd` | Go to the function (or the global) under the cursor |
| `Space` / `D` | Control flow graph of the function, on the block of the line |
| `i` `a` `A` `I` `o` `O` | Insert mode (arrows, `Enter`, `Backspace`, `Delete`, `Tab`), `Esc` goes back to the normal mode |
| `dd` | Delete the line (a count deletes several: `3dd`) |
| `v` / `V` | Visual mode, by characters / by lines: the moves extend the selection from where it started, `v` and `V` switch between the two (the same key leaves it), `Esc` leaves it |
| `y` (visual), `yy` / `Y` | Copy the selection to the clipboard, the line without one (a count copies several: `3yy`) |
| `d` / `x`, `c` / `s` (visual) | Delete the selection (change it: delete, then insert), by characters (the ends of the lines in it join the lines) or by lines, in one function; `e` goes to the end of the word in visual mode |
| `d` / `c` + `w` `e` `b` `$` `0` `^` `j` `k` `l` `h`, `cc` | Delete (change: delete then insert) to the next word, the end of the word, the previous word, the end / start / first character of the line, with the line below / above, a character after / before (`cw` changes to the end of the word as in vim, counts work: `3dw`) |
| `u` / `U` | Undo / redo |
| `cn` | Rename the variable, function or global under the cursor (`:rename`) |
| `ct` | Retype the variable under the cursor (`:retype`) |
| `cs` | Give a prototype to the function (`:sig`, prefilled with its current one) |
| `;` | Comment above the line |
| `gs` | The string literal under the cursor as text, C literal, bytes, shell argument and Python bytes, `Enter` copies one (`:string`) |
| `M` | Move the function to a module (`:mv`) |
| `]c` / `[c` | Next / previous conflict between the edits and the decompiled code |
| `x` / `C` | Cross references / call graph of the function |
| `L` | Ask the LLM to improve and document the function (names, types, summary, clear C keeping the addresses of its lines): its proposal shows in `:review` |

What is copied (`y`, `:string`) goes to the clipboard of the system and to the one of the terminal. The clipboard of
the system is the one of X11 (the Wayland sessions of GNOME and KDE share it through XWayland), of macOS or of
Windows; on Wayland without XWayland `wl-copy` (wl-clipboard) does it, `xclip` or `xsel` when X11 cannot be reached
directly. On Linux the copied text is served by execdump while it runs, then by the clipboard manager of the desktop
when there is one. The one of the terminal is OSC 52, for the terminals that support it (kitty, WezTerm, iTerm2,
foot, xterm, tmux with `set-clipboard on`), through ssh too; GNOME Terminal and the other VTE terminals ignore it.

In the review of the LLM proposals: `j` / `k` move, `n` / `p` go to the next / previous proposal, `a` accepts it, `r` rejects it, `Enter` opens the code of its function. Accepted proposals are merged into `main` on the next `:w`.

Commands:

| Command | Action |
|---|---|
| `:0x401000`, `:main` | Go to an address, a function or a symbol, by its name in the C code too (`:core_fmt_Arguments_new_v1`, `:sub_401000`, `:g_4c8b8`) |
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
| `:llm`, `:llm modules [module\|all]` | Ask the LLM to improve and document the current function / to organize the functions of a module (or of the program) |
| `:review`, `:accept <n>`, `:reject <n>` | Review the LLM proposals |
| `:toggle-explorer` (`:explorer`) | Show or hide the explorer |
| `:search-next`, `:search-previous`, `:clear-search` | Matches of the last search |
| `:delete <motion>`, `:change <motion>` | Operators of the C code (`word`, `word-end`, `word-back`, `line-end`, `line-start`, `line-first`, `line`, `down`, `up`, `char`, `char-back`) |
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

The LLM assistance uses the `[llm]` section:

```toml
# ~/.execdumprc
[llm]
backend = "anthropic"              # openai, anthropic, google, deepseek, mistral, groq, xai, openrouter, ollama, openai-compatible
model = "..."
api_key_env = "ANTHROPIC_API_KEY"  # or api_key = "..."
# base_url = "http://localhost:11434"
# max_tokens = 2048
# temperature = 0.2
# timeout = 120                    # seconds
```

execdump calls the APIs itself, in three formats: OpenAI chat completions (`openai`, `deepseek`, `mistral`, `groq`,
`xai`, `openrouter`, `ollama`, and any compatible server with `backend = "openai-compatible"` and its `base_url`,
`http://localhost:8080/v1` for llama.cpp for instance), Anthropic messages (`anthropic`) and Google Gemini (`google`).
`base_url` replaces the default address of a backend (with or without its version path, `/v1`), `ollama` and
`openai-compatible` need no key. Every backend works the same way:

- the answer is streamed, so a long rewrite is never cut by the timeout: it is the longest silence allowed
- `max_tokens` is always sent (the improvements of the TUI, the whole function, get at least 8192), an answer cut by it is an error saying to raise it
- the answer is a JSON object following a schema: the structured output of the API when it has one (JSON schema for
  OpenAI, Mistral, xAI, OpenRouter and Ollama, a forced tool for Anthropic, JSON mode for the others), and the schema
  is in the system prompt
- the errors give the HTTP status and what the API answered; the models that refuse a temperature are asked again
  without it

While the LLM works, the status line shows it with the time it has been running.

### Debugger

`:debug [arguments]` (or `F5`) runs the binary under gdb or lldb, to its first breakpoint, to `main` without one (the
entry point without `main`). The debug view opens on the right of the C code. At each stop the C code moves to the
line the program is at, with `▶` in its gutter and the line highlighted, in the module of its function: when a step
leaves the module, the code of the module of the new function replaces it (on the jumplist of its tab, `Ctrl-o` goes
back). The linear disassembly and the control flow graph of the function follow the program too.

The debug view shows:

- the variables of the function of the selected frame and their values, read where the decompiler says they are at
  that address (`--decompile storage`): a register (`edi`, `xmm0`), a stack slot from the stack pointer at the entry
  of the function (`[sp-0x48]`, the stack pointer is tracked through the instructions), a constant. Their shape gives
  how they are shown: integers by their size and sign, floats, `char` with its character, pointers to text with their
  string (`0x555555556004 "world"`), buffers of text as strings, the other buffers as bytes. A variable that is in no
  location at that address is `?`
- the watches (`:watch`, `:memory`): values and blocks of memory, what changed since the stop before highlighted.
  `Enter` (or `y`) on a watch or a variable shows its value in every form, as `:value` does
- the call stack, the functions of the program by their name (`depth+0x17`) with their module, the others by the
  name the debugger gives (the libraries); `Enter` on a frame selects it: the code, the variables, the registers and
  the watches are the ones of that frame (unwound by the debugger). `Ctrl-k` / `Ctrl-j` (or `Ctrl-Up` / `Ctrl-Down`,
  `:caller` / `:callee`) go up and down the call stack from anywhere, `F2` (`:stack`) shows it in a popup
- the registers, the breakpoints (`Enter` shows the code of one) and the last lines of the output of the program, as
  it writes them

Breakpoints are toggled on the line (or the instruction, or the node) under the cursor with `F9` or `gb`, or with
`:break <function or address>`; they are marked with `●` in the C code and the linear disassembly, kept while
execdump runs and given to the debugger at the load address of the program (PIE and ASLR).

| Keys | Command | Action |
|---|---|---|
| `F5` | `:continue` | Continue (start the program when it is not running) |
| `F7` | `:step` (`:s`) | Next line of C, into the functions of the program it calls |
| `F8` | `:step-over` (`:n`) | Next line of C of the function, over the calls |
| `F4` | `:finish` | Until the function returns |
| | `:stepi`, `:nexti` | One instruction, into or over the calls |
| `F6` | `:interrupt` | Stop the running program |
| `F9`, `gb` | `:break [function or address]` | Toggle a breakpoint |
| | `:frame <n>` | Select a frame of the call stack |
| `Ctrl-k` / `Ctrl-j` | `:caller` / `:callee` | Select the frame of the caller / of the callee |
| `F2` | `:stack` (`:bt`) | The call stack in a popup, `Enter` selects a frame |
| `w` (debug view), `gw` (C code, on the word) | `:watch <expression>` | Watch a value |
| `m` (debug view) | `:memory <address> [bytes]` | Watch a block of memory in hexadecimal (64 bytes by default, 4096 at most) |
| `dd` (debug view) | `:unwatch [n\|all]` | Stop watching (the watch under the cursor without a number) |
| `Enter`, `y` (debug view), `gy` (C code, on the word) | `:value [expression] [form]` | The value in every form, `Enter` copies one; with a form, copies it |
| `i` (debug view) | `:input [text]` | Send a line to the input of the program |
| | `:kill` | Kill the program and the debugger |

A watch is an expression: a variable of the function of the selected frame, a register, a function or a global of
the program, a number, plus or minus a number (`rsp+0x10`, without spaces), with `*` to read the word at its address
(`*rsp`) and `&` for the address of a variable in the stack (`&v18`). `:memory` takes the address of the block: the
value of a variable or of a register (`:memory a1 32` for the buffer a pointer points to), the address of a global
(`:memory buffer 256`). The values and the bytes that changed since the stop before are highlighted. On Linux the
memory is read from the process of the program (`/proc/<pid>/mem`, the program is a child of execdump), so the blocks
of memory and the values read from memory change live while the program runs (`Watches (live)`, the changes since
the last stop highlighted); elsewhere they are read at the stops. The watches stay from one run to the next.

`:value` takes the same expressions (the watch or the variable under the cursor of the debug view, the word under
the cursor of the C code without one) and shows the value in a popup, `Enter` copies a form to the clipboard: the
value as the debug view shows it, hexadecimal, what it points to (`0x5555555551e2 <main>`, the string as a C literal
and as text), the unsigned and signed integers of 1, 2, 4 and 8 bytes and the floats its first bytes make (in the
byte order of the program), the character, and its bytes (`e2 51 55 55`, a C array `{ 0xe2, 0x51, ... }`, a Python
`b"..."`, base64). A block of memory (`:memory`) gives its bytes and its text. With a form the value is copied
without the popup: `:value v3 u32`, `:value rdi string`, `:value *rsp hex`. The forms are `value`, `hex`, `pointer`,
`string`, `text`, `u8` to `i64`, `f32`, `f64`, `char`, `bytes`, `c`, `python` and `base64`.

A line of C is its address (the first instruction of its statement), a step continues to the addresses of the lines
of the function and to its return address with temporary breakpoints. A line is only a stop in the frame the step
started in: the stack pointer there, minus its offset from the entry of the function at that address, has to be the
stack pointer at the entry of the frame, so a recursive call does not stop the step. `:step` also stops at the entry
of the functions of the program the function calls (directly). A function not decompiled yet steps by instructions,
a step from a library returns to the program, a step from a caller selected in the call stack continues until the
program is back in it.

The program runs on a terminal of its own (a pseudo-terminal): its output and its errors are in the debug view as it
writes them (the C library flushes its output at each line on a terminal, it keeps it until its buffer is full in a
file), the escape sequences of the colors left out, and it reads what `:input` sends (echoed as a terminal does).
Without a pseudo-terminal (Windows) its output goes to a file and its input is empty. The debugger is gdb on Linux and lldb on macOS, the other one when it is the only one installed, or the one of the
`[debugger]` section:

```toml
# ~/.execdumprc
[debugger]
backend = "lldb"                   # gdb or lldb
# path = "/usr/bin/lldb-18"        # the executable, found in the PATH without it
```

gdb is driven through GDB/MI, lldb through its command line (with formats of its own for its stops and its frames),
see `crates/execdump-debugger`. `EXECDUMP_DEBUGGER_LOG=<file>` appends what execdump writes to the debugger and what
it answers to a file. The program of Go stops at `main.main` (its `main` is the entry of the runtime), a step into the
calls does not stop in the growth of the stack (`runtime.morestack`). The tests of the debugger build a small C program with `cc` and run it under each
debugger installed.

![tui](https://github.com/romainaugier/execdump/blob/main/res/tui.png)

## Acknowledgement

This tool is based on several amazing open-source projects (go check them out!) :
 - [Capstone](https://github.com/capstone-engine/capstone)
 - [Ratatui](https://ratatui.rs/)
 - [LLVM](https://llvm.org/)
 - [libgit2](https://libgit2.org/)

## Reporting a bug

`execdump --specs` prints what a bug report needs to know about the build and the machine, to paste in the issue:

```
execdump 0.1.0
commit    724f9bb1c3d2
build     release, x86_64-unknown-linux-gnu, rustc 1.97.0 (2d8144b78 2026-07-07)
llvm      18.1.3
capstone  5.0
os        Ubuntu 24.04.5 LTS
kernel    Linux 6.8.0-87-generic
arch      x86_64
cpu       AMD Ryzen 9 7950X 16-Core Processor (32 threads)
memory    62.5 GiB
terminal  xterm-256color, truecolor, 238x61
debugger  gdb at /usr/bin/gdb, GNU gdb (Ubuntu 15.1-1ubuntu1~24.04.1) 15.1
config    ~/.execdumprc
```

The commit is the one execdump was built from (`unknown` outside a git checkout). `arch` shows an emulated build (an
x64 build on Windows on ARM, an x86_64 one under Rosetta), the debugger is the one the TUI would run, and `config` says
whether `~/.execdumprc` parses. The paths under the home directory start with `~`, the report does not give the user name.

## Contributing

Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md): pull requests target `dev`, and everyone taking part
follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md).

## License

execdump is licensed under the [Apache License, Version 2.0](LICENSE). Every source file carries the
`SPDX-License-Identifier: Apache-2.0` line, except the programs under `tests/data/src` and `examples` that are built into
fixtures and samples.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in execdump is licensed as
above, without any additional terms or conditions (section 5 of the license).
