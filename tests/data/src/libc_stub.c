char *strcpy(char *dest, const char *src) { return dest; }
int printf(const char *format, ...) { return 0; }
int puts(const char *s) { return 0; }
__SIZE_TYPE__ strlen(const char *s) { return 0; }
void abort(void) { for (;;) {} }
void __stack_chk_fail(void) { for (;;) {} }
long __stack_chk_guard;
void qsort(void *base, __SIZE_TYPE__ count, __SIZE_TYPE__ size, int (*compare)(const void *, const void *)) {}
int strcmp(const char *a, const char *b) { return 0; }
void exit(int status) { for (;;) {} }
void *memset(void *s, int c, __SIZE_TYPE__ n) { return s; }
char *fgets(char *s, int n, void *stream) { return s; }
void *stdin;
void *malloc(__SIZE_TYPE__ size) { return 0; }
