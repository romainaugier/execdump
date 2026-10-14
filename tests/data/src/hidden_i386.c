/* 32-bit code hiding its instructions: a jump to an address computed in a register lands after the first byte
   of what reads as one instruction, the code is there. A buffer read with its size: the variables after it are
   not part of it */

int puts(const char *s);
char *fgets(char *s, int n, void *stream);
extern void *stdin;

int main(void)
{
    const char *key = "abcdefgh";
    char input[9];

    fgets(input, 9, stdin);

    __asm__ volatile("lea 1f, %%eax\n\tinc %%eax\n\tjmp *%%eax\n1:\n\t.byte 0xb8" ::: "eax");

    if (input[0] == key[3] && input[1] == key[5]) {
        puts("hidden");
        return 0;
    }

    return 1;
}

void _start(void)
{
    main();
}
