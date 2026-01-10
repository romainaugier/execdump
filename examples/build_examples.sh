#!/bin/bash

if [[ -e build ]]; then
    rm -rf build
fi

mkdir build

for file in *; do
    if [ -f "$file" ]; then
        echo "$file"

        if [ "$file" == *.cpp ]; then
            g++ "$file" -o build/"$file".out -O2
        else
            gcc "$file" -o build/"$file".out -O2
        fi
    fi
done
