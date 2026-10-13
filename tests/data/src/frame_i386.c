/* 32-bit unoptimized code: the locals live in the stack frame, buffers have their address taken */

char *strcpy(char *dest, const char *src);
int printf(const char *format, ...);
int puts(const char *s);

int check(const char *input)
{
    char buffer[32];
    char motto[12];
    int total = 0;
    int i;

    /* Written four bytes at a time, like the strings compilers put on the stack */
    *(int *)&motto[0] = 0x7362696c;
    *(int *)&motto[4] = 0x20797472;
    *(int *)&motto[8] = 0x00216f6b;

    strcpy(buffer, input);

    /* Read after the call that wrote the buffer */
    if (buffer[1] == 'x') {
        puts("second is x");
    }

    for (i = 0; i < 4; i++) {
        total += buffer[i];
    }

    printf("%s %d %f\n", motto, total, 2.5);
    return total;
}

void _start(void)
{
    check("example");
}
