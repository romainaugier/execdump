#!/bin/bash

if [[ -e build ]]; then
    rm -rf build
fi

mkdir build

for file in *; do
    if [ -f "$file" ]; then
        if [ "$file" == *.cpp ]; then
            g++ "$file" -o build/"$file".out -O2
        elif [ "$file" == *.c ]; then
            gcc "$file" -o build/"$file".out -O2
        elif [ "$file" == *linux.asm ]; then
            nasm "$file" -o build/"$file".out
        fi
    fi
done
