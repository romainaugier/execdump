/*
 * The allocator of Rust and the panics of its core library, for the decompiler (lang/rust)
 *
 * The names are the C names of the demangled paths (core::panicking::panic is core_panicking_panic). A &str is its
 * pointer then its length. Only the functions of scalar parameters: the layout of the others (fmt::Arguments) changes
 * with the version of Rust.
 */

struct rust_str {
    const char *ptr;
    size_t len;
};

struct rust_location {
    struct rust_str file;
    unsigned int line;
    unsigned int col;
};

void *__rust_alloc(size_t size, size_t align);
void *__rust_alloc_zeroed(size_t size, size_t align);
void __rust_dealloc(void *ptr, size_t size, size_t align);
void *__rust_realloc(void *ptr, size_t old_size, size_t align, size_t new_size);
void core_panicking_panic(const char *msg, size_t len, const struct rust_location *location);
void core_panicking_panic_bounds_check(size_t index, size_t len, const struct rust_location *location);
void core_panicking_panic_const_panic_const_add_overflow(const struct rust_location *location);
void core_panicking_panic_const_panic_const_sub_overflow(const struct rust_location *location);
void core_panicking_panic_const_panic_const_mul_overflow(const struct rust_location *location);
void core_panicking_panic_const_panic_const_div_by_zero(const struct rust_location *location);
void core_panicking_panic_const_panic_const_rem_by_zero(const struct rust_location *location);
void core_option_unwrap_failed(const struct rust_location *location);
void core_option_expect_failed(const char *msg, size_t len, const struct rust_location *location);
void core_result_unwrap_failed(const char *msg, size_t len, const void *error, const void *vtable, const struct rust_location *location);
void core_slice_index_slice_start_index_len_fail(size_t index, size_t len, const struct rust_location *location);
void core_slice_index_slice_end_index_len_fail(size_t index, size_t len, const struct rust_location *location);
void core_slice_index_slice_index_order_fail(size_t index, size_t end, const struct rust_location *location);
void alloc_alloc_handle_alloc_error(size_t align, size_t size);
void std_process_exit(int code);
