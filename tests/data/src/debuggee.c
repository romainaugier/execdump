/* Program run by the tests of the debugger (built when they run, with debuggee_util.c) */

#include <stdio.h>
#include <string.h>

int square_sum(int n);
int depth(int n);
void spin(void);

__attribute__((noinline)) void greet(const char *name)
{
    char buffer[64];
    strcpy(buffer, "hello ");
    strcat(buffer, name);
    puts(buffer);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "spin") == 0)
        spin();

    greet(argc > 1 ? argv[1] : "world");
    int sum = square_sum(argc + 3);
    printf("%d %d\n", sum, depth(3));
    return 0;
}
