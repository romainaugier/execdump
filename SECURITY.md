# Security Policy

execdump parses untrusted executables (PE, ELF, Mach-O, DWARF, Go and Rust metadata) and can run them under a debugger, so a crafted binary that makes it crash, hang, read or write out of bounds, or run code is a security issue.

## Supported versions

Only the latest release and the `dev` branch get fixes.

## Reporting a vulnerability

Do not open a public issue. Report it privately through [GitHub private vulnerability reporting](https://github.com/romainaugier/execdump/security/advisories/new) (Security tab, "Report a vulnerability"), with:

- the output of `execdump --specs` (version, commit, OS, architecture)
- the binary that triggers it, or how to build it (attach it to the report, not to a public issue)
- the command line or the TUI actions that lead to it, and what happens (backtrace, sanitizer output)

execdump is maintained on free time: reports are acknowledged as soon as possible. Once fixed, the advisory is published with the release that contains the fix, crediting you unless you ask otherwise.

Out of scope: running a binary under the debugger is running it, execdump does not sandbox the debuggee. The LLM features send the code of the functions to the endpoint set in `~/.execdumprc`.
