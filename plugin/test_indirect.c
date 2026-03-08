#include <stdio.h>

static void foo(void) {
    puts("foo");
}

int main(void) {
    void (*fp)(void) = foo;
    fp();
    return 0;
}
