/* Functions of the debuggee in a source file of their own: its static functions (the first and the last of the file,
 * built with -fno-toplevel-reorder) have FILE symbols, the functions between them are a module of their own in
 * execdump */

volatile int spinning = 1;

__attribute__((noinline)) static int square(int i)
{
    return i * i;
}

__attribute__((noinline)) int square_sum(int n)
{
    int total = 0;

    for (int i = 1; i <= n; i++)
        total += square(i);

    return total;
}

__attribute__((noinline)) int depth(int n)
{
    if (n == 0)
        return 0;

    return depth(n - 1) + 1;
}

__attribute__((noinline)) static int keep_spinning(void)
{
    return spinning;
}

__attribute__((noinline)) void spin(void)
{
    while (keep_spinning())
        ;
}
