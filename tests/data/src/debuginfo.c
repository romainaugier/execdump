// Debug information: the decompiler takes the names and the types of the functions, of their parameters, of the
// globals, and the structs, unions and enums of the program from it

int printf(const char *format, ...);
void *malloc(unsigned long size);

enum shape_kind { SHAPE_CIRCLE, SHAPE_RECT = 4, SHAPE_TRIANGLE };

typedef struct point {
    int x;
    int y;
} point_t;

struct shape {
    enum shape_kind kind;
    point_t origin;
    union {
        int radius;
        struct { short width; short height; } size;
    } dims;
    unsigned visible : 1;
    unsigned layer : 7;
    char name[12];
    double (*area)(const struct shape *self);
    struct shape *next;
};

struct shape *shapes;
int shape_count = 3;

static double rect_area(const struct shape *self) {
    return (double)self->dims.size.width * self->dims.size.height;
}

__attribute__((noinline)) struct shape *make_rect(int x, int y, short width, short height) {
    struct shape *shape = malloc(sizeof(struct shape));
    shape->kind = SHAPE_RECT;
    shape->origin.x = x;
    shape->origin.y = y;
    shape->dims.size.width = width;
    shape->dims.size.height = height;
    shape->visible = 1;
    shape->layer = 3;
    shape->area = rect_area;
    shape->next = shapes;
    shapes = shape;
    shape_count++;
    return shape;
}

__attribute__((noinline)) double total_area(const struct shape *list) {
    double total = 0;

    for (const struct shape *s = list; s; s = s->next) {
        if (s->visible) {
            total += s->area(s);
        }
    }

    return total;
}

int main(int argc, char **argv) {
    (void)argv;

    make_rect(argc, 2, 3, 4);
    printf("%f %d\n", total_area(shapes), shape_count);
    return 0;
}

void _start(void) {
    main(1, 0);

    for (;;) {}
}
