char *strcpy(char *dest, const char *src) { return dest; }
int printf(const char *format, ...) { return 0; }
int puts(const char *s) { return 0; }
__SIZE_TYPE__ strlen(const char *s) { return 0; }
void abort(void) { for (;;) {} }
void __stack_chk_fail(void) { for (;;) {} }
long __stack_chk_guard;
