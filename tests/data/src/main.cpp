extern "C" int lib_add(int a, int b);

namespace ns {
    int twice(int x) { return lib_add(x, x); }
}

extern "C" int main() { return ns::twice(21); }
