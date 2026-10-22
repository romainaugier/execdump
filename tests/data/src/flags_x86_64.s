# Code in a section without the flag of code (build_fixtures.sh clears it), as hand written headers have: the loader
# only reads the executable segment. The messages are not NUL terminated, write gets their length.
.intel_syntax noprefix
.globl _start

.section .rodata
hello: .ascii "hello\n"
bye: .ascii "bye\n"
path: .asciz "/tmp/x"

.text
_start:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + hello]
    mov edx, 6
    syscall
    mov eax, 2
    lea rdi, [rip + path]
    xor esi, esi
    syscall
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + bye]
    mov edx, 4
    syscall
    mov eax, 60
    xor edi, edi
    syscall
