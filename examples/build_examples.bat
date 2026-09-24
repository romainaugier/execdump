@echo off
setlocal enabledelayedexpansion

if exist build (
    rmdir /s /q build
)

mkdir build

for %%f in (*) do (
    set FILEPATH=%%f

    if "!FILEPATH:~-4!" equ ".cpp" (
        clang++ "%%f" -o "build/%%f.exe" -O2
        clang++ --target=aarch64-pc-windows-msvc "%%f" -o "build/%%f.arm64.exe" -O2
    )

    if "!FILEPATH:~-2!" equ ".c" (
        clang "%%f" -o "build/%%f.exe" -O2
        clang --target=aarch64-pc-windows-msvc "%%f" -o "build/%%f.arm64.exe" -O2
    )
)
