// Analysis fixture: calls, a switch compiled to a jump table, loops, a noreturn function and strings

int lib_add(int a, int b);

const char *messages[] = { "zero", "one", "two" };

__attribute__((noreturn, noinline)) void fatal(int code) {
    for (;;) {
        __asm__ volatile("" :: "r"(code));
    }
}

__attribute__((noinline)) int classify(int x) {
    switch (x) {
        case 0: return lib_add(x, 1);
        case 1: return x * 3 + lib_add(x, 7);
        case 2: return lib_add(x, x) - 5;
        case 3: return x << 4;
        case 4: return lib_add(2, x) * 9;
        case 5: return x ^ 0x55;
        case 6: return lib_add(x, 11) + 3;
        default: return -1;
    }
}

__attribute__((noinline)) int count_chars(const char *s) {
    int n = 0;

    while (s[n] != 0) {
        n++;
    }

    return n;
}

int main(int argc, char **argv) {
    (void)argv;

    int sum = 0;

    for (int i = 0; i < argc * 8; i++) {
        sum += classify(i);
    }

    sum += count_chars("hello from the analysis fixture");
    sum += count_chars(messages[argc % 3]);

    if (sum < 0) {
        fatal(sum);
    }

    return lib_add(sum, argc);
}

void _start(void) {
    main(1, 0);

    for (;;) {}
}
