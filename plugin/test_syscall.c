#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    syscall(SYS_getpid);
    return 0;
}
