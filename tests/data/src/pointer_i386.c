/* 32-bit unoptimized code: a function only ever called through a global pointer set to it, main's arguments, a
   buffer cleared by its initializer (rep stosd with gcc, memset with clang) */

char *strcpy(char *dest, const char *src);
int strcmp(const char *a, const char *b);
int puts(const char *s);
int printf(const char *format, ...);
void exit(int status);

void verify(const char *input, const char *expected)
{
    if (strcmp(input, expected) == 0) {
        puts("granted");
    }
}

int main(int argc, char **argv)
{
    static void (*check)(const char *, const char *);
    char copy[32];
    char expected[100] = {0};

    if (argc != 2) {
        printf("usage: %s password\n", argv[0]);
        exit(1);
    }

    check = verify;
    strcpy(copy, argv[1]);
    strcpy(expected, "secret");
    check(copy, expected);
    return 0;
}

void _start(void)
{
    main(0, 0);
}
