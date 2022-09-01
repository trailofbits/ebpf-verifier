#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <linux/bpf.h>

#ifdef __v5_18__
  // bpf_sys_bpf is a convenient global
  extern int bpf_sys_bpf(int, union bpf_attr *, uint32_t);
#elif __v5_2__
  extern int lauras_sys_bpf(int, union bpf_attr *, unsigned int);
#else
  extern int sys_bpf(int, union bpf_attr *, uint32_t);
#endif

long int my_syscall(long int __sysno, ...) {
  va_list args;
  long int arg0, arg1, arg2, arg3, arg4, arg5;

  /* Load varargs */
  va_start (args, __sysno);
  arg0 = va_arg (args, long int);
  arg1 = va_arg (args, long int);
  arg2 = va_arg (args, long int);
  arg3 = va_arg (args, long int);
  arg4 = va_arg (args, long int);
  arg5 = va_arg (args, long int);
  va_end (args);

#ifdef __v5_18__
  return bpf_sys_bpf((int) arg0, (union bpf_attr *)arg1, (uint32_t) arg2);
#elif __v5_2__
  return lauras_sys_bpf((int) arg0, (union bpf_attr *)arg1, (unsigned int) arg2);
#else
  return sys_bpf((int) arg0, (union bpf_attr *)arg1, (uint32_t) arg2);
#endif
}
