# execdump

execdump is a command-line tool that helps you analyze Windows's PE and Linux's ELF files by parsing and printing the required information about them, or navigate through them using a terminal-based ui.

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
      --sections
          Dumps the Sections
      --sections-filter <SECTIONS_FILTER>
          Regulax expresion to filter the Sections to display [default: .*]
      --sections-data
          Dumps the Sections data along with the headers
      --disasm
          Disassemble the code found in the Sections containing code
      --pe-import
          Dump all the PE data related to imports, if any
      --pe-import-directory-table
          Dump the Import Directory Table, if any
      --pe-hint-name-table
          Dump the Hint/Name Table, if any
      --pe-dlls
          Dump the DLLs names imported, if any
      --pe-debug-directory
          Dump the debug information from the Debug Directory, if any
      --pe-exc-table
          Dump the exception information from the Exception Table, if any
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

- :x: Export Table
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

Not supported yet.

### Core

Utilities:
  - :x: C++ Symbol Demangler

PE/ELF Disasm:
  - :x: Replace call addresses with symbols
  - :x: Structure program
  - :x: Easily find system calls

### TUI

Viewers:
  - :heavy_check_mark: Headers
  - :clock9: PE Sections
  - :x: ELF Sections
  - :heavy_check_mark: Hex Viewer
  - :x: Disasm Viewer

## Acknowledgement

This tool is based on several amazing open-source projects (go check them out!) :
 - [Capstone](https://github.com/capstone-engine/capstone)
 - [Ratatui](https://ratatui.rs/)
