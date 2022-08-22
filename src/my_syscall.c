#include <stdint.h>
#include <stdlib.h>

#include <stdarg.h>
// #include <stdio.h>
#include <linux/bpf.h> // TODO: make sure this is being included from correct place


extern int bpf_sys_bpf(int, union bpf_attr *, uint32_t);

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

  // printf("my_syscall triggered with sysno: %ld and cmd: %ld\n", __sysno, arg0);

  return bpf_sys_bpf((int) arg0, (union bpf_attr *)arg1, (uint32_t) arg2);
}
