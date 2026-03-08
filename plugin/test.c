#include <stdio.h>

static void foo(void) {
    puts("foo");
}

static void bar(void) {
    foo();
}

int main(void) {
    bar();
    puts("hello");
    return 0;
}
