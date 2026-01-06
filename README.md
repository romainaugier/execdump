# pedump

pedump is a command-line tool that helps you analyze Windows's Portable Executable files by parsing and printing the required information about them.

This project is currently a work in progress so not everything is supported, and it might be broken.

pedump might evolve into a library later, instead of just being a standalone command-line tool.

## Usage

Usage: `pedump.exe [OPTIONS] <FILE_PATH>`

Arguments:
  <FILE_PATH>

Options:
      --dos-header       Dumps the legacy MS-DOS compatible header
      --nt-header        Dumps the NT Header (most recent)
      --optional-header  Dumps the Optional (either 32/64) header
  -h, --help             Print help
  -V, --version          Print version
