# Assembly passing values in the registers it chooses (the crackmes of root-me): the checksum of the code takes its
# bounds in eax and ebx and returns it in ecx, the program exits with a system call the next function follows
.intel_syntax noprefix
.globl _start

.data
key: .byte 0x0a, 0x1e, 0xcd, 0x2a
input: .space 4

.text
_start:
    mov eax, 3
    xor ebx, ebx
    lea ecx, [input]
    mov edx, 4
    int 0x80
    mov eax, offset _start
    mov ebx, offset end
    call checksum
    mov edx, ecx
    mov ecx, 4
check:
    ror edx, 1
    mov al, [key + ecx - 1]
    xor al, [input + ecx - 1]
    xor al, dl
    jne fail
    dec ecx
    jne check
    mov eax, 1
    xor ebx, ebx
    int 0x80
fail:
    mov eax, 1
    mov ebx, 1
    int 0x80

checksum:
    sub ebx, eax
    xor ecx, ecx
next:
    add cl, [eax]
    rol ecx, 3
    inc eax
    dec ebx
    jne next
    ret
end:
