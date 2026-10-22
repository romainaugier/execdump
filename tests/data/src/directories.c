// PE data directories: a function of a DLL loaded at its first call (delay load), a TLS callback (it runs before
// the entry point), the load configuration with Control Flow Guard (the functions called through a pointer)

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;

int lib_delayed(int x);

volatile int sink;

static void __stdcall on_thread(void *module, unsigned long reason, void *reserved) {
    sink += (int)reason;
}

__attribute__((noinline)) static int twice(int x) { return x * 2; }
__attribute__((noinline)) static int square(int x) { return x * x; }

int (*volatile operations[])(int) = { twice, square };

// What the C runtime defines: the TLS directory, the delay load helper, the load configuration
int _tls_index;
void (__stdcall *const tls_callbacks[])(void *, unsigned long, void *) = { on_thread, 0 };
const struct { u64 start, end, index, callbacks; u32 zero_fill, characteristics; } _tls_used = { 0, 0, (u64)&_tls_index, (u64)tls_callbacks, 0, 0 };

void *__delayLoadHelper2(const void *descriptor, void **slot) { return *slot; }

u64 __security_cookie = 0x2b992ddfa232;
static void guard_check(void) {}
void (*__guard_check_icall_fptr)(void) = guard_check;
void (*__guard_dispatch_icall_fptr)(void) = guard_check;
extern char __guard_fids_table[], __guard_fids_count[];

const struct {
    u32 size, time;
    u16 major, minor;
    u32 global_flags_clear, global_flags_set, critical_section_timeout;
    u64 decommit_block, decommit_total, lock_prefix, max_allocation, virtual_memory, affinity;
    u32 heap_flags;
    u16 csd_version, dependent_load_flags;
    u64 edit_list, security_cookie, se_handlers, se_handler_count, guard_check, guard_dispatch, guard_functions, guard_function_count;
    u32 guard_flags;
} _load_config_used = {
    .size = sizeof(_load_config_used),
    .security_cookie = (u64)&__security_cookie,
    .guard_check = (u64)&__guard_check_icall_fptr,
    .guard_dispatch = (u64)&__guard_dispatch_icall_fptr,
    .guard_functions = (u64)__guard_fids_table,
    .guard_function_count = (u64)__guard_fids_count,
    // Instrumented, with a functions table
    .guard_flags = 0x500,
};

void mainCRTStartup(void) {
    sink = operations[sink & 1](sink) + lib_delayed(sink);
}
