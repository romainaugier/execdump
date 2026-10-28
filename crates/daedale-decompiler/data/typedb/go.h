/*
 * The runtime of Go and a few functions of its standard library, for the decompiler (lang/go)
 *
 * One parameter per machine word, as the decompiler shows them: a string is its pointer then its length, a slice its
 * array, its length and its capacity, an interface its type (or itab) then its data. The results after the first one
 * are the pointers named ret_* after the parameters. A prototype is used for a function when the size of its
 * arguments and results is the one the pclntab gives (the runtime of another version is not taken for this one).
 * The layouts are the ones of 64-bit targets since Go 1.10. The types of the maps and of the channels extend
 * go_type with a layout of their version: they are pointers.
 */

struct go_type {
    uint64_t size;
    uint64_t ptrdata;
    unsigned int hash;
    uint8_t tflag;
    uint8_t align;
    uint8_t field_align;
    uint8_t kind;
    void *equal;
    uint8_t *gcdata;
    int str;
    int ptr_to_this;
};

struct go_itab {
    struct go_type *inter;
    struct go_type *type;
    unsigned int hash;
    uint8_t pad[4];
    void *fun[1];
};

struct go_string {
    const char *str;
    int64_t len;
};

struct go_slice {
    void *array;
    int64_t len;
    int64_t cap;
};

struct go_iface {
    struct go_itab *tab;
    void *data;
};

struct go_eface {
    struct go_type *type;
    void *data;
};

void *runtime_newobject(struct go_type *typ);
void *runtime_newarray(struct go_type *typ, int64_t n);
void *runtime_mallocgc(uint64_t size, struct go_type *typ, bool needzero);
void *runtime_makeslice(struct go_type *et, int64_t len, int64_t cap);
void *runtime_growslice(void *old, int64_t new_len, int64_t old_cap, int64_t num, struct go_type *et, int64_t *ret_len, int64_t *ret_cap);
void *runtime_makechan(void *t, int64_t size);
void runtime_chansend1(void *c, void *elem);
void runtime_chanrecv1(void *c, void *elem);
bool runtime_chanrecv2(void *c, void *elem);
void runtime_closechan(void *c);
void *runtime_makemap(void *t, int64_t hint, void *h);
void *runtime_makemap_small(void);
void *runtime_mapaccess1(void *t, void *h, void *key);
void *runtime_mapaccess2(void *t, void *h, void *key, bool *ret_ok);
void *runtime_mapaccess1_fast32(void *t, void *h, uint32_t key);
void *runtime_mapaccess1_fast64(void *t, void *h, uint64_t key);
void *runtime_mapaccess1_faststr(void *t, void *h, const char *key, int64_t key_len);
void *runtime_mapaccess2_faststr(void *t, void *h, const char *key, int64_t key_len, bool *ret_ok);
void *runtime_mapassign(void *t, void *h, void *key);
void *runtime_mapassign_fast32(void *t, void *h, uint32_t key);
void *runtime_mapassign_fast64(void *t, void *h, uint64_t key);
void *runtime_mapassign_faststr(void *t, void *h, const char *key, int64_t key_len);
void runtime_mapdelete(void *t, void *h, void *key);
void *runtime_convT(struct go_type *t, void *v);
void *runtime_convTnoptr(struct go_type *t, void *v);
void *runtime_convT16(uint16_t val);
void *runtime_convT32(unsigned int val);
void *runtime_convT64(uint64_t val);
void *runtime_convTstring(const char *str, int64_t len);
void *runtime_convTslice(void *array, int64_t len, int64_t cap);
const char *runtime_concatstring2(void *buf, const char *a, int64_t a_len, const char *b, int64_t b_len, int64_t *ret_len);
const char *runtime_concatstring3(void *buf, const char *a, int64_t a_len, const char *b, int64_t b_len, const char *c, int64_t c_len, int64_t *ret_len);
const char *runtime_concatstring4(void *buf, const char *a, int64_t a_len, const char *b, int64_t b_len, const char *c, int64_t c_len, const char *d, int64_t d_len, int64_t *ret_len);
const char *runtime_slicebytetostring(void *buf, const uint8_t *ptr, int64_t n, int64_t *ret_len);
void *runtime_stringtoslicebyte(void *buf, const char *s, int64_t len, int64_t *ret_len, int64_t *ret_cap);
const char *runtime_intstring(void *buf, int64_t v, int64_t *ret_len);
int64_t runtime_cmpstring(const char *a, int64_t a_len, const char *b, int64_t b_len);
void runtime_typedmemmove(struct go_type *typ, void *dst, void *src);
void runtime_typedmemclr(struct go_type *typ, void *ptr);
bool runtime_ifaceeq(struct go_itab *tab, void *x, void *y);
bool runtime_efaceeq(struct go_type *t, void *x, void *y);
void runtime_gopanic(struct go_type *type, void *data);
void runtime_throw(const char *s, int64_t len);
void runtime_printstring(const char *s, int64_t len);
void runtime_printint(int64_t v);
void runtime_printuint(uint64_t v);
void runtime_printpointer(void *p);
void runtime_printbool(bool v);
int64_t fmt_Println(struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Print(struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Printf(const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Fprintln(struct go_itab *w, void *w_data, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Fprint(struct go_itab *w, void *w_data, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Fprintf(struct go_itab *w, void *w_data, const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
const char *fmt_Sprintf(const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, int64_t *ret_len);
const char *fmt_Sprint(struct go_eface *a, int64_t len, int64_t cap, int64_t *ret_len);
const char *fmt_Sprintln(struct go_eface *a, int64_t len, int64_t cap, int64_t *ret_len);
struct go_itab *fmt_Errorf(const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, void **ret_data);
int64_t fmt_Scanln(struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Scan(struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Scanf(const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
int64_t fmt_Sscanf(const char *str, int64_t str_len, const char *format, int64_t format_len, struct go_eface *a, int64_t len, int64_t cap, struct go_itab **ret_err, void **ret_err_data);
struct go_itab *errors_New(const char *text, int64_t len, void **ret_data);
const char *strconv_Itoa(int64_t i, int64_t *ret_len);
int64_t strconv_Atoi(const char *s, int64_t len, struct go_itab **ret_err, void **ret_err_data);
const char *strconv_FormatInt(int64_t i, int64_t base, int64_t *ret_len);
int64_t strconv_ParseInt(const char *s, int64_t len, int64_t base, int64_t bit_size, struct go_itab **ret_err, void **ret_err_data);
int64_t bytes_Compare(const uint8_t *a, int64_t a_len, int64_t a_cap, const uint8_t *b, int64_t b_len, int64_t b_cap);
bool bytes_Equal(const uint8_t *a, int64_t a_len, int64_t a_cap, const uint8_t *b, int64_t b_len, int64_t b_cap);
int64_t strings_Index(const char *s, int64_t len, const char *substr, int64_t substr_len);
bool strings_Contains(const char *s, int64_t len, const char *substr, int64_t substr_len);
bool strings_HasPrefix(const char *s, int64_t len, const char *prefix, int64_t prefix_len);
bool strings_HasSuffix(const char *s, int64_t len, const char *suffix, int64_t suffix_len);
const char *strings_ToUpper(const char *s, int64_t len, int64_t *ret_len);
const char *strings_ToLower(const char *s, int64_t len, int64_t *ret_len);
const char *strings_TrimSpace(const char *s, int64_t len, int64_t *ret_len);
const char *strings_Repeat(const char *s, int64_t len, int64_t count, int64_t *ret_len);
void os_Exit(int64_t code);
const char *os_Getenv(const char *key, int64_t len, int64_t *ret_len);
