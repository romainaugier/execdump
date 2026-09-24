int add(int a, int b) { return a + b; }

int big(int n) {
    volatile int arr[64];

    for (int i = 0; i < 64; i++)
        arr[i] = add(i, n);

    return arr[n & 63];
}

int mainCRTStartup() { return big(3); }
