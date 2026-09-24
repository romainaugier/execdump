#!/bin/bash

if [[ -e build ]]; then
    rm -rf build
fi

mkdir build

if [[ "$(uname)" == "Darwin" ]]; then
    for file in *; do
        if [[ -f "$file" ]]; then
            if [[ "$file" == *.cpp ]]; then
                clang++ "$file" -o build/"$file".out -O2 -arch arm64 -arch x86_64
            elif [[ "$file" == *.c ]]; then
                clang "$file" -o build/"$file".out -O2 -arch arm64 -arch x86_64
            fi
        fi
    done

    exit 0
fi

for file in *; do
    if [[ -f "$file" ]]; then
        if [[ "$file" == *.cpp ]]; then
            g++ "$file" -o build/"$file".out -O2

            if command -v aarch64-linux-gnu-g++ > /dev/null; then
                aarch64-linux-gnu-g++ "$file" -o build/"$file".aarch64.out -O2
            fi
        elif [[ "$file" == *.c ]]; then
            gcc "$file" -o build/"$file".out -O2

            if command -v aarch64-linux-gnu-gcc > /dev/null; then
                aarch64-linux-gnu-gcc "$file" -o build/"$file".aarch64.out -O2
            fi
        elif [[ "$file" == *linux.asm ]]; then
            nasm "$file" -o build/"$file".out
        elif [[ "$file" == *linux_aarch64.s ]]; then
            clang --target=aarch64-linux-gnu -nostdlib -static -fuse-ld=lld "$file" -o build/"$file".out
        fi
    fi
done
