#!/bin/bash
# Rebuilds the test fixtures, requires clang and lld (ld.lld, ld64.lld, lld-link, llvm-lipo), gcc for x86_64 and rustc

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

# ELF x86_64 whose section of code does not have the flag of code (cleared after the link, as hand written headers
# leave it): the code is the one of the executable segment
clang --target=x86_64-linux-gnu -c src/flags_x86_64.s -o "$TMP"/flags.o
"$LLVM_BIN"/ld.lld --strip-all --build-id=none -e _start "$TMP"/flags.o -o elf_x86_64_section_flags
python3 - elf_x86_64_section_flags <<'PYTHON'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
shoff, = struct.unpack_from('<Q', data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
strtab, = struct.unpack_from('<Q', data, shoff + shstrndx * shentsize + 0x18)
for i in range(shnum):
    header = shoff + i * shentsize
    name, = struct.unpack_from('<I', data, header)
    if data[strtab + name:data.index(0, strtab + name)] == b'.text':
        flags, = struct.unpack_from('<Q', data, header + 8)
        struct.pack_into('<Q', data, header + 8, flags & ~0x4)
open(path, 'wb').write(data)
PYTHON

# ELF x86_64, dynamically linked against a shared library
clang --target=x86_64-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libfoo.so src/lib.c -o "$TMP"/libfoo_x86_64.so
clang --target=x86_64-linux-gnu -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=sha1 src/main_nostdlib.c "$TMP"/libfoo_x86_64.so -o elf_x86_64_dyn

# ELF x86_64, optimized code for the analysis (jump table, loops, noreturn, strings)
clang --target=x86_64-linux-gnu -O2 -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    src/analysis.c "$TMP"/libfoo_x86_64.so -o elf_x86_64_analysis

# ELF aarch64, switches compiled to jump tables (entries of one and two bytes, a biased index)
clang --target=aarch64-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libfoo.so src/lib.c -o "$TMP"/libfoo_aarch64.so
clang --target=aarch64-linux-gnu -O2 -nostdlib -fPIE -pie -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux-aarch64.so.1 \
    -Wl,--build-id=none src/switch.c "$TMP"/libfoo_aarch64.so -o elf_aarch64_switch

# ELF i386, unoptimized (locals in the stack frame), against a stub libc
clang --target=i386-linux-gnu -nostdlib -fPIC -shared -fuse-ld=lld -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc.so.6
clang --target=i386-linux-gnu -O0 -fno-pie -no-pie -nostdlib -fno-stack-protector -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux.so.2 \
    -Wl,--build-id=none src/frame_i386.c "$TMP"/libc.so.6 -o elf_i386_frame
clang --target=i386-linux-gnu -O0 -fno-pie -no-pie -nostdlib -fno-stack-protector -fuse-ld=lld -Wl,--dynamic-linker,/lib/ld-linux.so.2 \
    -Wl,--build-id=none src/pointer_i386.c "$TMP"/libc.so.6 -o elf_i386_pointer
# Code hidden behind a jump into the middle of an instruction, a buffer read with its size
gcc -m32 -O0 -fno-pie -fno-stack-protector -fcf-protection=none -c src/hidden_i386.c -o "$TMP"/hidden.o
"$LLVM_BIN"/ld.lld -m elf_i386 --dynamic-linker /lib/ld-linux.so.2 --build-id=none -e _start "$TMP"/hidden.o "$TMP"/libc.so.6 -o elf_i386_hidden
# The same built by gcc (its realigned frame for main, rep stosd, overlapping stores of strings)
gcc -m32 -O0 -fno-pie -fno-stack-protector -fcf-protection=none -c src/pointer_i386.c -o "$TMP"/pointer_gcc.o
"$LLVM_BIN"/ld.lld -m elf_i386 --dynamic-linker /lib/ld-linux.so.2 --build-id=none -e _start "$TMP"/pointer_gcc.o "$TMP"/libc.so.6 -o elf_i386_pointer_gcc

# Assembly passing values in the registers it chooses, exiting with a system call
clang --target=i386-linux-gnu -c src/registers_i386.s -o "$TMP"/registers.o
"$LLVM_BIN"/ld.lld -m elf_i386 --strip-all --build-id=none -e _start "$TMP"/registers.o -o elf_i386_registers
# Position independent code of x86 built by gcc: ebx holds the global offset table, the local functions take their
# arguments in registers, __stack_chk_fail_local has no name once stripped
gcc -m32 -O2 -fPIC -fstack-protector-strong -fcf-protection=none -c src/pic_i386.c -o "$TMP"/pic.o
"$LLVM_BIN"/ld.lld -m elf_i386 -shared --strip-all --build-id=none -soname libpic.so "$TMP"/pic.o "$TMP"/libc.so.6 -o elf_i386_pic

# Optimized code with the stack protector (thread canary on x86, __stack_chk_guard on aarch64), a switch split
# by the compiler and small functions, built by gcc on x86_64 (its own patterns: hot and cold parts)
gcc -O2 -fPIC -shared -nostdlib -fno-stack-protector -Wl,-soname,libc.so.6 src/libc_stub.c -o "$TMP"/libc_x86_64.so.6
gcc -O2 -fstack-protector-strong -fcf-protection=none -fno-pie -no-pie -nostdlib -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=none src/quality.c "$TMP"/libc_x86_64.so.6 -o elf_x86_64_quality
# Debug information (DWARF 5, compressed): the types, prototypes and names the decompiler takes from it
gcc -g -gz=zlib -O1 -fno-pie -no-pie -nostdlib -fno-stack-protector -fcf-protection=none -Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
    -Wl,--build-id=none src/debuginfo.c "$TMP"/libc_x86_64.so.6 -o elf_x86_64_debuginfo
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

# PE x86_64 with a delay loaded DLL, a TLS callback and Control Flow Guard (the C runtime parts are in the source)
"$LLVM_BIN"/clang-cl --target=x86_64-pc-windows-msvc /O1 /guard:cf /c src/delayed.c /Fo"$TMP"/delayed.obj
"$LLVM_BIN"/lld-link /dll /noentry /nodefaultlib /export:lib_delayed /out:"$TMP"/delayed.dll /implib:"$TMP"/delayed.lib "$TMP"/delayed.obj
"$LLVM_BIN"/clang-cl --target=x86_64-pc-windows-msvc /O1 /guard:cf /GS- /c src/directories.c /Fo"$TMP"/directories.obj
"$LLVM_BIN"/lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /guard:cf /delayload:delayed.dll \
    /out:pe_x86_64_directories.exe "$TMP"/directories.obj "$TMP"/delayed.lib

# Mach-O x86_64 executable linked against a dylib and a stub libSystem
clang --target=x86_64-apple-macos11 -c src/lib.c -o "$TMP"/lib.o
clang --target=x86_64-apple-macos11 -c src/dyld_stub_binder.c -o "$TMP"/dyld_stub_binder.o
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -dylib -install_name @rpath/libfoo.dylib "$TMP"/lib.o -o "$TMP"/libfoo.dylib
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -dylib -install_name /usr/lib/libSystem.B.dylib "$TMP"/dyld_stub_binder.o -o "$TMP"/libSystem.dylib
clang++ --target=x86_64-apple-macos11 -O1 -c src/main.cpp -o "$TMP"/main_x86_64.o
"$LLVM_BIN"/ld64.lld -arch x86_64 -platform_version macos 11.0 11.0 -e _main -rpath @loader_path \
    "$TMP"/main_x86_64.o "$TMP"/libfoo.dylib "$TMP"/libSystem.dylib -o macho_x86_64

# Mach-O arm64 executables with pointers in data (rebases) and imports referenced from data (binds), linked with
# chained fixups and with the opcodes of Dyld Info
clang --target=arm64-apple-macos13 -c src/libfoo_data.c -o "$TMP"/libfoo_data.o
clang --target=arm64-apple-macos13 -c src/dyld_stub_binder.c -o "$TMP"/dyld_stub_binder_arm64.o
"$LLVM_BIN"/ld64.lld -arch arm64 -platform_version macos 13.0 13.0 -dylib -install_name @rpath/libfoo.dylib "$TMP"/libfoo_data.o -o "$TMP"/libfoo_arm64.dylib
"$LLVM_BIN"/ld64.lld -arch arm64 -platform_version macos 13.0 13.0 -dylib -install_name /usr/lib/libSystem.B.dylib "$TMP"/dyld_stub_binder_arm64.o -o "$TMP"/libSystem_arm64.dylib
clang --target=arm64-apple-macos13 -O1 -c src/fixups.c -o "$TMP"/fixups.o
"$LLVM_BIN"/ld64.lld -arch arm64 -platform_version macos 13.0 13.0 -e _main -rpath @loader_path -fixup_chains \
    "$TMP"/fixups.o "$TMP"/libfoo_arm64.dylib "$TMP"/libSystem_arm64.dylib -o macho_arm64_chained
"$LLVM_BIN"/ld64.lld -arch arm64 -platform_version macos 13.0 13.0 -e _main -rpath @loader_path -no_fixup_chains \
    "$TMP"/fixups.o "$TMP"/libfoo_arm64.dylib "$TMP"/libSystem_arm64.dylib -o macho_arm64_dyld_info

# Mach-O fat object (arm64 + x86_64)
clang++ --target=arm64-apple-macos11 -O1 -c src/main.cpp -o "$TMP"/main_arm64.o
"$LLVM_BIN"/llvm-lipo -create "$TMP"/main_arm64.o "$TMP"/main_x86_64.o -output macho_fat.o

# ELF x86_64 PIE in Rust without std: legacy and v0 mangled names, a call to core through a GOT slot the loader
# fills (R_X86_64_RELATIVE)
RUSTC_BOOTSTRAP=1 rustc -O --edition 2021 -C panic=abort -C relocation-model=pie -C strip=debuginfo -Z unstable-options \
    -C symbol-mangling-version=legacy -C link-arg=-nostartfiles -C link-arg=-nostdlib -C link-arg=-Wl,--build-id=none \
    src/rust.rs -o elf_x86_64_rust

# The same with string literals: &str passed to a function, returned in two registers and in a static table
RUSTC_BOOTSTRAP=1 rustc -O --edition 2021 -C panic=abort -C relocation-model=pie -C strip=debuginfo -Z unstable-options \
    -C symbol-mangling-version=legacy -C link-arg=-nostartfiles -C link-arg=-nostdlib -C link-arg=-Wl,--build-id=none \
    src/rust_strings.rs -o elf_x86_64_rust_strings
