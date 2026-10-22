// Pointers the loader writes: a table of strings and of local functions (rebases), imported functions and an
// imported object referenced from data (binds)

int lib_add(int a, int b);
int lib_mul(int a, int b);
extern int lib_counter;

static int twice(int x) { return x * 2; }
static int square(int x) { return x * x; }

const char *names[] = { "alpha", "beta", "gamma" };
int (*locals[])(int) = { twice, square };
int (*imported[])(int, int) = { lib_add, lib_mul };
int *counter = &lib_counter;

__attribute__((noinline)) int apply(int i, int x) {
    return imported[i & 1](locals[i & 1](x), *counter) + names[i % 3][0];
}

int main(int argc, char **argv) {
    (void)argv;
    return apply(argc, argc + 1);
}
