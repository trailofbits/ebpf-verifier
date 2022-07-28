#include <stdlib.h>
#include <sys/syscall.h>
#include <stdarg.h>

extern long int syscall (long int __sysno,...);
extern void abort(void);

inline long int my_syscall(long int __sysno, ...) {
  va_list args;
  long int arg0, arg1, arg2, arg3, arg4, arg5;

  if (__sysno == 280) {
    abort();
  }
  /* Load varargs */
  va_start (args, __sysno);
  arg0 = va_arg (args, long int);
  arg1 = va_arg (args, long int);
  arg2 = va_arg (args, long int);
  arg3 = va_arg (args, long int);
  arg4 = va_arg (args, long int);
  arg5 = va_arg (args, long int);
  va_end (args);

  return syscall(__sysno, arg0, arg1, arg2, arg3, arg4, arg5);
};
