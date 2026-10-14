#!/bin/bash
# Rebuilds the test fixtures, requires clang and lld (ld.lld, ld64.lld, lld-link, llvm-lipo), and gcc for x86_64

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

# ELF i386, unoptimized (locals in the stack frame), against a stub libc
clang --target=i386-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc.so.6
clang --target=i386-linux-gnu -O0 -fno-pie -no-pie -nostdlib -fno-stack-protector -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux.so.2 \
    -Wl,--build-id=none src/frame_i386.c "$TMP"/libc.so.6 -o elf_i386_frame
clang --target=i386-linux-gnu -O0 -fno-pie -no-pie -nostdlib -fno-stack-protector -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux.so.2 \
    -Wl,--build-id=none src/pointer_i386.c "$TMP"/libc.so.6 -o elf_i386_pointer
# The same built by gcc (its realigned frame for main, rep stosd, overlapping stores of strings)
gcc -m32 -O0 -fno-pie -fno-stack-protector -fcf-protection=none -c src/pointer_i386.c -o "$TMP"/pointer_gcc.o
"$LLVM_BIN"/ld.lld -m elf_i386 --dynamic-linker /lib/ld-linux.so.2 --build-id=none -e _start "$TMP"/pointer_gcc.o "$TMP"/libc.so.6 -o elf_i386_pointer_gcc

# Optimized code with the stack protector (thread canary on x86, __stack_chk_guard on aarch64), a switch split
# by the compiler and small functions, built by gcc on x86_64 (its own patterns: hot and cold parts)
gcc -O2 -fPIC -shared -nostdlib -fno-stack-protector -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc_x86_64.so.6
gcc -O2 -fstack-protector-strong -fcf-protection=none -fno-pie -no-pie -nostdlib -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=none src/quality.c "$TMP"/libc_x86_64.so.6 -o elf_x86_64_quality
# Structs passed between functions
gcc -O1 -fno-pie -no-pie -nostdlib -fno-stack-protector -fcf-protection=none -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=none src/structs.c "$TMP"/libc_x86_64.so.6 -o elf_x86_64_structs
clang --target=i386-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc_i386.so.6
clang --target=i386-linux-gnu -O2 -fstack-protector-strong -fno-pic -no-pie -nostdlib -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux.so.2 \
    -Wl,--build-id=none src/quality.c "$TMP"/libc_i386.so.6 -o elf_i386_quality
clang --target=aarch64-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc_aarch64.so.6
clang --target=aarch64-linux-gnu -O2 -fstack-protector-strong -fPIE -pie -nostdlib -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux-aarch64.so.1 \
    -Wl,--build-id=none src/quality.c "$TMP"/libc_aarch64.so.6 -o elf_aarch64_quality

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
