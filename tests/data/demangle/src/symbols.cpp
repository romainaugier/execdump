// Exercises as many mangling features as possible without any standard header,
// so it compiles for every target (Linux, macOS, MinGW, MSVC)

namespace std {
    template <class T> struct allocator {};
    template <class C> struct char_traits {};
    template <class C, class T = char_traits<C>, class A = allocator<C>> struct basic_string { basic_string(); ~basic_string(); };
    template <class C, class T = char_traits<C>> struct basic_ostream { basic_ostream& operator<<(const C*); };
    typedef basic_string<char> string;
    typedef basic_ostream<char> ostream;
    template <class T, class A = allocator<T>> struct vector { void push_back(const T&); T& operator[](unsigned long); };
    typedef decltype(nullptr) nullptr_t;
}

namespace ns {
    struct Base {
        virtual ~Base();
        virtual int value() const;
        int field;
        static int counter;
    };

    struct Other {
        virtual void other();
    };

    struct Derived : Base, Other {
        Derived();
        Derived(const Derived&);
        Derived(Derived&&);
        ~Derived() override;
        int value() const override;
        void other() override;
        Derived& operator=(const Derived&);
        bool operator==(const Derived&) const;
        int operator[](int) const;
        int operator()(int, char) &;
        int operator()(int, char) &&;
        operator int() const;
        void* operator new(decltype(sizeof(0)));
        void operator delete(void*);
        Derived& operator+=(int);
        Derived operator-() const;
        bool operator!() const;
        Derived& operator++();
        Derived operator++(int);
        int operator->*(int);
        void volatile_method() volatile;
        static void static_method();
    };

    struct Virtual : virtual Base {
        int value() const override;
    };

    template <class T> struct Box {
        T value;
        Box();
        T get() const;
        template <class U> U convert(U) const;
        static T instance;
    };

    template <int N> struct Int {};
    template <bool B> struct Bool {};
    template <int* P> struct Ptr {};

    enum Color { Red, Green };
    enum class Scoped : unsigned char { A, B };
    union Union { int i; float f; };

    int global_array[4];
    int global;

    void free_function();
    void overloaded(int);
    void overloaded(unsigned int, long long, unsigned long long);
    void overloaded(char, signed char, unsigned char, short, unsigned short);
    void overloaded(float, double, long double, bool, wchar_t);
    void overloaded(char16_t, char32_t);
    void overloaded(const char*, volatile int*, const volatile void*);
    void overloaded(int&, int&&, const int&);
    void overloaded(int (*)(char), void (Base::*)(), int Base::*);
    void overloaded(int (&)[4], int (*)[4][5]);
    void overloaded(Color, Scoped, Union);
    void overloaded(std::nullptr_t);
    void overloaded(const std::string&, std::ostream&);
    void overloaded(std::vector<int>, std::vector<std::vector<Box<int>>>);
    void overloaded(Int<0>, Int<-1>, Int<42>, Bool<true>, Ptr<&global>);
    void variadic(int, ...);
    template <class... Ts> void pack(Ts...);
    template <class T> T* template_function(T, const T&);
    template <class T, int N> void array_ref(T (&)[N]);
    auto trailing(int) -> decltype(global);
    int noexcept_function() noexcept;
    void function_pointer_noexcept(void (*)() noexcept);

    namespace {
        void anonymous();
    }

    inline namespace v1 {
        void inline_namespace();
    }

    int with_local_static() {
        static int local = global;
        struct Local { static int get() { return 1; } };
        return local + Local::get();
    }

    int with_lambda() {
        auto lambda = [](int x) { return x * 2; };
        auto generic = [](auto x) { return x; };
        return lambda(1) + generic(2);
    }

    const char* string_literal() {
        return "hello world";
    }

    struct DtorOnly {
        ~DtorOnly();
    };

    DtorOnly global_with_dtor;
}

int ns::Base::counter;
template <class T> T ns::Box<T>::instance;

extern "C" void c_function();

void* use_everything() {
    ns::Derived d;
    ns::Virtual v;
    ns::Box<int> b;
    ns::Box<ns::Box<double>> bb;
    static int arr[4];

    ns::free_function();
    ns::overloaded(1);
    ns::overloaded(1u, 1ll, 1ull);
    ns::overloaded('a', (signed char)1, (unsigned char)1, (short)1, (unsigned short)1);
    ns::overloaded(1.0f, 1.0, 1.0L, true, L'a');
    ns::overloaded(u'a', U'a');
    ns::overloaded("a", (volatile int*)0, (const volatile void*)0);
    int i = 0;
    ns::overloaded(i, 1, 1);
    ns::overloaded((int (*)(char))0, (void (ns::Base::*)())0, &ns::Base::field);
    ns::overloaded(arr, (int (*)[4][5])0);
    ns::overloaded(ns::Red, ns::Scoped::A, ns::Union{});
    ns::overloaded(nullptr);
    ns::overloaded(*(std::string*)0, *(std::ostream*)0);
    ns::overloaded(std::vector<int>(), std::vector<std::vector<ns::Box<int>>>());
    ns::overloaded(ns::Int<0>(), ns::Int<-1>(), ns::Int<42>(), ns::Bool<true>(), ns::Ptr<&ns::global>());
    ns::variadic(1, 2, 3);
    ns::pack(1, 2.0, 'c');
    ns::pack();
    ns::template_function(1, 2);
    ns::template_function(b, b);
    ns::array_ref(arr);
    ns::trailing(1);
    ns::noexcept_function();
    ns::function_pointer_noexcept(nullptr);
    ns::anonymous();
    ns::inline_namespace();
    ns::with_local_static();
    ns::with_lambda();
    ns::string_literal();
    c_function();

    d = d;
    d == d;
    d[1];
    d(1, 'c');
    static_cast<ns::Derived&&>(d)(1, 'c');
    (int)d;
    d += 1;
    -d;
    !d;
    ++d;
    d++;
    d->*1;
    d.volatile_method();
    ns::Derived::static_method();
    b.get();
    b.convert(1.5f);
    bb.get();
    std::vector<int>()[0];
    std::vector<int>().push_back(1);
    *(std::ostream*)0 << "x";

    return new ns::Derived(d) + ns::Box<char>::instance + ns::Base::counter + ns::global_array[0];
}
