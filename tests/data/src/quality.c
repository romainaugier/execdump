/* Optimized code with the stack protector: buffers, a switch the compiler splits, small functions that
   only call another one */

char *strcpy(char *dest, const char *src);
__SIZE_TYPE__ strlen(const char *s);
int printf(const char *format, ...);
int puts(const char *s);
void abort(void);

int state;

__attribute__((noinline, noreturn)) void fatal(void)
{
    abort();
}

__attribute__((noinline)) int length_of(const char *text)
{
    char buffer[64];

    strcpy(buffer, text);

    if (buffer[0] == 0) {
        fatal();
    }

    return (int)strlen(buffer) + buffer[1];
}

__attribute__((noinline)) int forward(const char *text, int unused)
{
    return length_of(text);
}

__attribute__((noinline)) int answer(void)
{
    return 42;
}

/* Sparse keys first, then a dense range in a jump table, the default is shared */
__attribute__((noinline)) int parse_opt(int key, const char *arg)
{
    char buffer[32];

    strcpy(buffer, arg);

    switch (key) {
        case 0x1000003:
            return puts(buffer);
        case 0x1000005:
            state = 9;
            return 0;
        case 'a':
            state = 1;
            return 0;
        case 'c':
            return length_of(buffer);
        case 'd':
            state = 3;
            return 0;
        case 'f':
            state = 4;
            return printf("%s\n", buffer);
        case 'g':
            state = 5;
            return 0;
        case 'k':
            state = 6;
            return forward(arg, 1);
        case 'p':
            return answer();
        default:
            return 7;
    }
}

/* Variables joined after the branches */
__attribute__((noinline)) int joined(int a, int b)
{
    int x = a;
    int y = b;

    if (a > b) {
        x = b;
        y = a;
    }

    while (x < y) {
        x += puts("step");
    }

    return x + y;
}

/* A pointer in and out */
__attribute__((noinline)) char *skip_spaces(char *text)
{
    while (*text == ' ') {
        text++;
    }

    return text;
}

int results;

void _start(void)
{
    results = parse_opt(state, skip_spaces("  abc")) + joined(state, 3);
    for (;;) {
    }
}
