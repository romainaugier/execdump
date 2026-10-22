/* Position independent code of x86: the globals and the PLT through ebx set by __x86.get_pc_thunk.bx, the local
 * functions gcc passes the arguments of in registers, the stack protector failing through __stack_chk_fail_local */
__SIZE_TYPE__ strlen(const char *s);
int puts(const char *s);
char *strcpy(char *dest, const char *src);
void __stack_chk_fail(void);

__attribute__((visibility("hidden"))) void __stack_chk_fail_local(void) { __stack_chk_fail(); }

int counter;
static const char *names[] = { "zero", "one", "two" };

static __attribute__((noinline)) int weigh(const char *text, int factor)
{
    int weight = 0;

    while (*text) {
        weight += *text++ * factor;
    }

    return weight;
}

int lib_weigh(const char *text)
{
    counter++;
    return weigh(text, 3) + weigh(names[counter % 3], 2);
}

int lib_copy(const char *text)
{
    char buffer[32];
    strcpy(buffer, text);
    puts(buffer);
    return strlen(buffer) + counter;
}
