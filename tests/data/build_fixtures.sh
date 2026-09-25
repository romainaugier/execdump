#!/bin/bash
# Rebuilds the test fixtures, requires clang and lld (ld.lld, ld64.lld, lld-link, llvm-lipo)

set -e

cd "$(dirname "$0")"

LLVM_BIN=${LLVM_BIN:-$(dirname "$(readlink -f "$(command -v clang)")")}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ELF aarch64, static
clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld src/hello_world_asm_linux_aarch64.s -o elf_aarch64_static

# ELF aarch64, dynamically linked against a shared library
clang --target=aarch64-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libfoo.so src/lib.c -o "$TMP"/libfoo.so
clang --target=aarch64-linux-gnu -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux-aarch64.so.1 \
    -Wl,--build-id=sha1 src/main_nostdlib.c "$TMP"/libfoo.so -o elf_aarch64_dyn

# ELF x86_64, dynamically linked against a shared library
clang --target=x86_64-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libfoo.so src/lib.c -o "$TMP"/libfoo_x86_64.so
clang --target=x86_64-linux-gnu -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=sha1 src/main_nostdlib.c "$TMP"/libfoo_x86_64.so -o elf_x86_64_dyn

# ELF x86_64, optimized code for the analysis (jump table, loops, noreturn, strings)
clang --target=x86_64-linux-gnu -O2 -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    src/analysis.c "$TMP"/libfoo_x86_64.so -o elf_x86_64_analysis

# PE ARM64
clang --target=aarch64-pc-windows-msvc -O1 -c src/main_windows.c -o "$TMP"/main_windows.obj
"$LLVM_BIN"/lld-link /Brepro /entry:mainCRTStartup /subsystem:console /nodefaultlib /out:pe_arm64.exe "$TMP"/main_windows.obj

# Mach-O x86_64 executable linked against a dylib and a stub libSystem
clang --target=x86_64-apple-macos11 -c src/lib.c -o "$TMP"/lib.o
clang --target=x86_64-apple-macos11 -c src/dyld_stub_binder.c -o "$TMP"/dyld_stub_binder.o
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -dylib -install_name @rpath/libfoo.dylib "$TMP"/lib.o -o "$TMP"/libfoo.dylib
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -dylib -install_name /usr/lib/libSystem.B.dylib "$TMP"/dyld_stub_binder.o -o "$TMP"/libSystem.dylib
clang++ --target=x86_64-apple-macos11 -O1 -c src/main.cpp -o "$TMP"/main_x86_64.o
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -e _main -rpath @loader_path \
    "$TMP"/main_x86_64.o "$TMP"/libfoo.dylib "$TMP"/libSystem.dylib -o macho_x86_64

# Mach-O fat object (arm64 + x86_64)
clang++ --target=arm64-apple-macos11 -O1 -c src/main.cpp -o "$TMP"/main_arm64.o
"$LLVM_BIN"/llvm-lipo -create "$TMP"/main_arm64.o "$TMP"/main_x86_64.o -output macho_fat.o
