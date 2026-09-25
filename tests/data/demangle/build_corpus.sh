#!/bin/bash
# Rebuilds the demangling corpus from symbols.cpp compiled for every supported ABI/OS,
# the expected output comes from llvm-cxxfilt (Itanium) and llvm-undname (MSVC).
# Requires clang and LLVM 18 tools (llvm-nm, llvm-cxxfilt, llvm-undname).

set -e

cd "$(dirname "$0")"

LLVM_BIN=${LLVM_BIN:-$(dirname "$(readlink -f "$(command -v clang)")")}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ITANIUM_TARGETS="x86_64-linux-gnu aarch64-linux-gnu arm64-apple-macos11 x86_64-apple-macos11 x86_64-w64-windows-gnu i686-w64-windows-gnu"
MSVC_TARGETS="x86_64-pc-windows-msvc i686-pc-windows-msvc aarch64-pc-windows-msvc arm64ec-pc-windows-msvc"

symbols() {
    clang++ --target="$1" -std=c++17 -O0 -w -c src/symbols.cpp -o "$TMP/$1.o"
    "$LLVM_BIN"/llvm-nm --no-sort "$TMP/$1.o" | awk '{print $NF}' | sort -u
}

for target in $ITANIUM_TARGETS; do
    # Mach-O and 32-bit Windows add a leading underscore to every symbol
    case "$target" in
        *apple* | i686-*) strip_underscore="-_" ;;
        *) strip_underscore="" ;;
    esac

    symbols "$target" | grep -E '^_{1,4}Z' > "$TMP/$target.sym" || true
    paste "$TMP/$target.sym" <("$LLVM_BIN"/llvm-cxxfilt $strip_underscore < "$TMP/$target.sym") | awk -F'\t' '$1 != $2' > "$target.tsv"
done

for target in $MSVC_TARGETS; do
    : > "$target.tsv"

    for symbol in $(symbols "$target" | grep -E '^\?'); do
        # llvm-undname 18 does not know the ARM64EC $$h marker, which does not change the demangled name
        demangled=$("$LLVM_BIN"/llvm-undname "${symbol//\$\$h/}" | sed -n 2p)

        if [[ -n "$demangled" && "$demangled" != error* ]]; then
            printf '%s\t%s\n' "$symbol" "$demangled" >> "$target.tsv"
        fi
    done
done

# Larger corpora: LLVM's own MSVC demangler tests, a sample of libcxxabi's Itanium demangler tests
# and a sample of the host libstdc++ exported symbols (with their ELF symbol versions)
LLVM_RAW=https://raw.githubusercontent.com/llvm/llvm-project/release/18.x
MS_TESTS="arg-qualifiers back-references basic conversion-operators cxx11 cxx14 cxx17-noexcept cxx20 md5 mangle
          nested-scopes operators return-qualifiers string-literals template-callback templates templates-memptrs
          templates-memptrs-2 thunks windows"

: > llvm-ms-tests.tsv

for test in $MS_TESTS; do
    curl -sSf "$LLVM_RAW/llvm/test/Demangle/ms-$test.test" | grep -E '^[?.]' | while read -r symbol; do
        demangled=$("$LLVM_BIN"/llvm-undname "$symbol" | sed -n 2p)

        if [[ -n "$demangled" && "$demangled" != error* ]]; then
            printf '%s\t%s\n' "$symbol" "$demangled" >> llvm-ms-tests.tsv
        fi
    done
done

curl -sSf "$LLVM_RAW/libcxxabi/test/test_demangle.pass.cpp" \
    | grep -oE '^ *\{"_Z[^"\\]*",' | sed -E 's/^ *\{"//; s/",$//' | awk 'NR % 16 == 0' > "$TMP/cxxabi.sym"
paste "$TMP/cxxabi.sym" <("$LLVM_BIN"/llvm-cxxfilt < "$TMP/cxxabi.sym") | awk -F'\t' '$1 != $2' > libcxxabi-tests.tsv

LIBSTDCXX=$(find /usr/lib -name 'libstdc++.so.6' | head -1)
"$LLVM_BIN"/llvm-nm -D --defined-only "$LIBSTDCXX" | awk '{print $NF}' | grep '^_Z' | sort -u | awk 'NR % 8 == 0' > "$TMP/libstdcxx.sym"
paste "$TMP/libstdcxx.sym" <("$LLVM_BIN"/llvm-cxxfilt < "$TMP/libstdcxx.sym") | awk -F'\t' '$1 != $2' > libstdcxx.tsv
