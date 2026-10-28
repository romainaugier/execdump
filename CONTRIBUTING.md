# Contributing to daedale

Thanks for helping! Bug reports, decompilation samples, fixes and features are all welcome. By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go through [SECURITY.md](SECURITY.md), never a public issue.

## Issues

Use the templates: a bug, wrong decompiled code, or a feature. Paste the output of `daedale --specs` (the build, the machine and the platform). For anything about a given binary, the more of it you can share the better: the binary itself (or how to build it), its format and architecture, the function address and the exact command. Check that the bug still happens on `dev` first.

## Workflow

- `dev` is the development branch: fork, branch from `dev` and open the pull request against `dev`.
- `main` is the release branch: every push to it with a new `version` in `Cargo.toml` builds and publishes a release. Pull requests do not touch the version.
- Keep a pull request to one change. Discuss large ones (a new format, architecture or language, a new view in the TUI) in an issue first.
- The CI builds and tests on Linux (x86_64, arm64), Windows (x64, arm64) and macOS (arm64): it has to pass.

## Building and testing

The [Building](README.md#building) section of the README explains how to get LLVM 18 (`get_llvm.sh` installs only what is needed). Then:

```
cargo build
cargo test --workspace
```

- The debugger tests build a small C program with `cc` and run it under gdb or lldb, the ones that are installed.
- The fixtures in `tests/data` are committed binaries. To add one, add its source to `tests/data/src` and its build to `tests/data/build_fixtures.sh` (clang, lld, gcc and rustc), and commit the source, the script and the binary.
- The demangling corpus is rebuilt with `tests/data/demangle/build_corpus.sh`.
- A change to the decompiler is checked on real binaries with the sweep (see the README): run it before and after with `SWEEP_REPORT`/`SWEEP_BASELINE` and say in the pull request what got better or worse.

## Code

- Every new source file starts with `// SPDX-License-Identifier: Apache-2.0` (`# ...` in scripts), followed by a block comment saying what the module does, like the existing ones.
- Prefer explicit code to comments: clear names and small functions. Add a comment only for what the code cannot say (an ABI or format quirk, why an obvious approach does not work).
- Performance and memory footprint matter: daedale has to stay fast on binaries of any size. Avoid copies, allocations in hot loops and large enum variants that waste memory.
- Errors go through `anyhow`. Data read from the binary is untrusted: a malformed input must give an error, not a panic, so avoid new `unwrap()`s on it.
- Match the formatting of the code around: the tree is not `rustfmt`-formatted, do not reformat code you do not change.
- Add a test with the change: a unit test next to the code, or a fixture for format and decompiler work.
- Update the README when the change is visible to users (options, commands, the Features list).

## Commits

One logical change per commit, a short first line saying what it does (`bugfix: ...` for fixes), and a body explaining why when it is not obvious.

## License

daedale is licensed under the [Apache License 2.0](LICENSE). Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in daedale is licensed the same way, without any additional terms or conditions.
