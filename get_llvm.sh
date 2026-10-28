#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch static LLVM 18 libraries for daedale.
#
#   linux-x86_64, linux-arm64, macos-arm64   prebuilt release tarballs (any host)
#   macos-x86_64                             built from source (macOS host)
#   windows-x86_64, windows-arm64            built from source (Windows host, MSVC x64/arm64 env)
#
#   The Windows release tarball cannot be linked by llvm-sys: llvm-config asks for libxml2s.lib, which is not shipped.
#
#   For linux: install libtinfo.5 (dnf install ncurses-compat-libs)
#
# Usage: ./get_llvm.sh [-o OUTDIR] [-j JOBS] [-k] [TARGET...]
#   TARGET: one or more of the names above, "all", or "host" (default: host)
#   -o      install root, each target goes to OUTDIR/<target> (default: ./third_party/llvm)
#   -j      parallel jobs for source builds
#   -k      keep downloaded archives and build trees
#
# Environment:
#   LLVM_VERSION            default 18.1.8
#   LLVM_TARGETS            backends for source builds (default: X86;AArch64, the ones daedale initializes)
#   LLVM_MSVC_RUNTIME       CMAKE_MSVC_RUNTIME_LIBRARY for windows targets (default: MultiThreadedDLL, /MD like rustc)
#   LLVM_NATIVE_TOOL_DIR    dir with host llvm-tblgen etc. when cross-compiling a windows target

set -euo pipefail

LLVM_VERSION="${LLVM_VERSION:-18.1.8}"
LLVM_TARGETS="${LLVM_TARGETS:-X86;AArch64}"
LLVM_MSVC_RUNTIME="${LLVM_MSVC_RUNTIME:-MultiThreadedDLL}"
RELEASE_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}"

ALL_TARGETS=(linux-x86_64 linux-arm64 macos-x86_64 macos-arm64 windows-x86_64 windows-arm64)

OUT_DIR="$PWD/third_party/llvm"
JOBS=""
KEEP=0

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

usage() {
    sed -n '4,24p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

host_os() {
    case "$(uname -s)" in
        Linux*) echo linux ;;
        Darwin*) echo macos ;;
        MINGW*|MSYS*|CYGWIN*) echo windows ;;
        *) die "unknown host OS: $(uname -s)" ;;
    esac
}

host_arch() {
    local m
    m="$(uname -m)"
    # x64 Git Bash runs emulated on Windows on ARM, ask Windows instead
    if [[ "$(host_os)" == windows ]]; then
        m="${PROCESSOR_ARCHITEW6432:-${PROCESSOR_ARCHITECTURE:-$m}}"
    fi
    case "$m" in
        x86_64|amd64|AMD64) echo x86_64 ;;
        aarch64|arm64|ARM64) echo arm64 ;;
        *) die "unknown host arch: $(uname -m)" ;;
    esac
}

native_path() {
    if command -v cygpath >/dev/null; then
        cygpath -m "$1"
    else
        echo "$1"
    fi
}

host_jobs() {
    nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "${NUMBER_OF_PROCESSORS:-4}"
}

prebuilt_archive() {
    case "$1" in
        linux-x86_64)   echo "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz" ;;
        linux-arm64)    echo "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu.tar.xz" ;;
        macos-arm64)    echo "clang+llvm-${LLVM_VERSION}-arm64-apple-macos11.tar.xz" ;;
        *) echo "" ;;
    esac
}

download() {
    local url="$1" dst="$2"
    if [[ -s "$dst" ]]; then
        log "using cached $(basename "$dst")"
        return
    fi
    log "downloading $(basename "$dst")"
    curl -fL --progress-bar --retry 3 --retry-delay 2 -o "$dst.part" "$url"
    mv "$dst.part" "$dst"
}

# Only what is needed to link: headers, static libs, cmake package, llvm-config.
extract_libs() {
    local target="$1" archive="$2" dst="$3" root
    root="$(basename "$archive" .tar.xz)"

    local members=("$root/include/llvm" "$root/include/llvm-c" "$root/lib/cmake/llvm"
                   "$root/lib/libLLVM*.a" "$root/lib/libPolly*.a" "$root/bin/llvm-config")

    local wildcards=()
    tar --version 2>/dev/null | grep -q 'GNU tar' && wildcards=(--wildcards)

    local tmp="$dst.tmp"
    rm -rf "$tmp" && mkdir -p "$tmp"
    log "extracting to $dst"
    # Polly is not in every tarball, tar fails on unmatched members so check the result instead
    tar -xJf "$archive" -C "$tmp" --strip-components=1 ${wildcards[@]+"${wildcards[@]}"} "${members[@]}" 2>/dev/null || true

    [[ -f "$tmp/include/llvm/Config/llvm-config.h" ]] || die "$archive: headers missing after extraction"
    [[ -f "$tmp/lib/cmake/llvm/LLVMConfig.cmake" ]] || die "$archive: cmake package missing after extraction"
    compgen -G "$tmp/lib/*LLVMSupport.*" >/dev/null || die "$archive: libraries missing after extraction"

    prune_cmake_exports "$tmp"
    rm -rf "$dst" && mv "$tmp" "$dst"
}

# LLVMExports checks every imported target's file exists, drop the checks for the tools we did not extract.
prune_cmake_exports() {
    local prefix="$1" f line
    local re='_(IMPORT_CHECK_FILES_FOR|cmake_import_check_files_for)_.*"\$\{_IMPORT_PREFIX\}/([^"]+)"'
    for f in "$prefix"/lib/cmake/llvm/LLVMExports-*.cmake; do
        [[ -f "$f" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" =~ $re ]] && [[ ! -e "$prefix/${BASH_REMATCH[2]}" ]]; then
                continue
            fi
            printf '%s\n' "$line"
        done < "$f" > "$f.new"
        mv "$f.new" "$f"
    done
}

fetch_prebuilt() {
    local target="$1" archive
    archive="$(prebuilt_archive "$target")"
    download "$RELEASE_URL/$archive" "$DL_DIR/$archive"
    extract_libs "$target" "$DL_DIR/$archive" "$OUT_DIR/$target"
    [[ $KEEP -eq 1 ]] || rm -f "$DL_DIR/$archive"
}

fetch_sources() {
    local archive="llvm-project-${LLVM_VERSION}.src.tar.xz"
    local src="$DL_DIR/llvm-project-${LLVM_VERSION}.src"
    if [[ ! -d "$src/llvm" ]]; then
        download "$RELEASE_URL/$archive" "$DL_DIR/$archive"
        log "extracting sources"
        tar -xJf "$DL_DIR/$archive" -C "$DL_DIR" \
            "llvm-project-${LLVM_VERSION}.src/llvm" \
            "llvm-project-${LLVM_VERSION}.src/cmake" \
            "llvm-project-${LLVM_VERSION}.src/third-party"
    fi
    echo "$src"
}

build_from_source() {
    local target="$1"; shift
    local src build prefix
    src="$(fetch_sources)"
    build="$DL_DIR/build-$target"
    prefix="$OUT_DIR/$target"

    command -v cmake >/dev/null || die "cmake is required to build $target"
    command -v ninja >/dev/null || die "ninja is required to build $target"

    log "configuring $target"
    cmake -S "$(native_path "$src/llvm")" -B "$(native_path "$build")" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$(native_path "$prefix")" \
        -DLLVM_TARGETS_TO_BUILD="$LLVM_TARGETS" \
        -DLLVM_ENABLE_PROJECTS= \
        -DLLVM_ENABLE_RUNTIMES= \
        -DBUILD_SHARED_LIBS=OFF \
        -DLLVM_BUILD_LLVM_DYLIB=OFF \
        -DLLVM_ENABLE_ZLIB=OFF \
        -DLLVM_ENABLE_ZSTD=OFF \
        -DLLVM_ENABLE_LIBXML2=OFF \
        -DLLVM_ENABLE_TERMINFO=OFF \
        -DLLVM_ENABLE_LIBEDIT=OFF \
        -DLLVM_ENABLE_LIBPFM=OFF \
        -DLLVM_ENABLE_BINDINGS=OFF \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF \
        -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_INCLUDE_DOCS=OFF \
        -DLLVM_INCLUDE_UTILS=OFF \
        -DLLVM_DISTRIBUTION_COMPONENTS="llvm-libraries;llvm-headers;cmake-exports;llvm-config" \
        "$@"

    log "building $target ($JOBS jobs)"
    cmake --build "$(native_path "$build")" --target install-distribution -j "$JOBS"

    [[ $KEEP -eq 1 ]] || rm -rf "$build"
}

build_macos_x86_64() {
    [[ "$(host_os)" == macos ]] || die "macos-x86_64 has no official build and must be built on a macOS host"
    if [[ "$(host_arch)" == arm64 ]] && ! arch -x86_64 /usr/bin/true 2>/dev/null; then
        die "building x86_64 on Apple Silicon runs x86_64 tablegen, install Rosetta: softwareupdate --install-rosetta"
    fi
    build_from_source macos-x86_64 \
        -DCMAKE_OSX_ARCHITECTURES=x86_64 \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
        -DLLVM_HOST_TRIPLE=x86_64-apple-darwin \
        -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-apple-darwin
}

build_windows() {
    local target="$1" arch processor triple
    case "$target" in
        windows-x86_64) arch=x64;   processor=AMD64; triple=x86_64-pc-windows-msvc ;;
        windows-arm64)  arch=arm64; processor=ARM64; triple=aarch64-pc-windows-msvc ;;
    esac

    [[ "$(host_os)" == windows ]] || die "$target has no linkable static build and must be built on a Windows host"
    command -v cl >/dev/null || die "cl.exe not found, run from a VS Developer shell (vcvarsall $arch)"
    [[ "${VSCMD_ARG_TGT_ARCH:-}" == "$arch" ]] || die "MSVC environment targets '${VSCMD_ARG_TGT_ARCH:-?}', expected $arch"

    local cross=()
    if [[ "${VSCMD_ARG_HOST_ARCH:-$arch}" != "$arch" ]]; then
        [[ -n "${LLVM_NATIVE_TOOL_DIR:-}" ]] \
            || die "cross-compiling from ${VSCMD_ARG_HOST_ARCH}: set LLVM_NATIVE_TOOL_DIR to a dir with host llvm-tblgen.exe, or build on a $arch machine"
        cross=(
            -DCMAKE_SYSTEM_NAME=Windows
            -DCMAKE_SYSTEM_PROCESSOR="$processor"
            -DLLVM_NATIVE_TOOL_DIR="$(native_path "$LLVM_NATIVE_TOOL_DIR")"
        )
    fi

    build_from_source "$target" \
        -DCMAKE_C_COMPILER=cl \
        -DCMAKE_CXX_COMPILER=cl \
        -DCMAKE_MSVC_RUNTIME_LIBRARY="$LLVM_MSVC_RUNTIME" \
        -DLLVM_ENABLE_DIA_SDK=OFF \
        -DLLVM_HOST_TRIPLE="$triple" \
        -DLLVM_DEFAULT_TARGET_TRIPLE="$triple" \
        ${cross[@]+"${cross[@]}"}
}

fetch_target() {
    local target="$1"
    if [[ -f "$OUT_DIR/$target/.llvm-$LLVM_VERSION" ]]; then
        log "$target: LLVM $LLVM_VERSION already installed"
        return
    fi
    log "$target"
    case "$target" in
        macos-x86_64) build_macos_x86_64 ;;
        windows-*)    build_windows "$target" ;;
        *)            fetch_prebuilt "$target" ;;
    esac
    touch "$OUT_DIR/$target/.llvm-$LLVM_VERSION"
}

while getopts "o:j:kh" opt; do
    case "$opt" in
        o) OUT_DIR="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        k) KEEP=1 ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done
shift $((OPTIND - 1))

[[ -n "$JOBS" ]] || JOBS="$(host_jobs)"

targets=()
for t in "${@:-host}"; do
    case "$t" in
        all)  targets+=("${ALL_TARGETS[@]}") ;;
        host) targets+=("$(host_os)-$(host_arch)") ;;
        *)
            [[ " ${ALL_TARGETS[*]} " == *" $t "* ]] || die "unknown target '$t' (expected: ${ALL_TARGETS[*]}, all, host)"
            targets+=("$t")
            ;;
    esac
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
DL_DIR="$OUT_DIR/.cache"
mkdir -p "$DL_DIR"

failed=()
for t in "${targets[@]}"; do
    set +e
    (set -e; fetch_target "$t")
    rc=$?
    set -e
    [[ $rc -eq 0 ]] || failed+=("$t")
done

[[ $KEEP -eq 1 ]] || rm -rf "$DL_DIR"

if [[ ${#failed[@]} -gt 0 ]]; then
    die "failed: ${failed[*]}"
fi
log "done: ${targets[*]} -> $OUT_DIR"
