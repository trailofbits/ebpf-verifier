#ifdef __v5_2__
#include <linux/syscalls.h>

#undef SYSCALL_DEFINE3
#define SYSCALL_DEFINE3(name, b, cmd, x, uattr, y, size)	\
long lauras_sys_##name(b cmd, x uattr, y size)

#endif
