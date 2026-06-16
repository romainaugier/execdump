BITS 64

global _start

section .data
    msg db "Hello World!", 13, 0

section .code

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg]
    mov rdx, 13
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
