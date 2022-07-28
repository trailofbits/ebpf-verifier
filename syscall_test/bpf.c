#include <stdarg.h>

extern long int syscall (long int __sysno, ...);

int bpf() {
	int res = syscall(5, 5);
	if (res == 666) {
		return 0;
	} else {
		return -1;
	}
}
