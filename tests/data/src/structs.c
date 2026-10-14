/* Structs passed between functions: the callers see the struct their callees recovered */

int puts(const char *s);

struct node {
    struct node *next;
    long value;
    int flags;
    char *name;
};

__attribute__((noinline)) long sum(struct node *n)
{
    long total = 0;

    for (; n; n = n->next) {
        total += n->value;
    }

    return total;
}

__attribute__((noinline)) long first(struct node *n)
{
    return sum(n) + n->value;
}

__attribute__((noinline)) int named(struct node *n)
{
    return n->name != 0 && (n->flags & 4) != 0;
}

__attribute__((noinline)) long walk(struct node *n)
{
    if (named(n)) {
        puts(n->name);
        return first(n) + n->flags;
    }

    return 0;
}

static struct node nodes[2];

void _start(void)
{
    nodes[0].next = &nodes[1];
    walk(&nodes[0]);
}
