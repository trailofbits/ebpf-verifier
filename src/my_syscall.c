#include <stdlib.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <stdio.h>
#include <linux/bpf.h> // TODO: make sure this is being included from correct place
#include "test.h"

extern long int syscall (long int __sysno,...);
extern int bpf_btf_load(union bpf_attr *, bpfptr_t);
extern int map_create(union bpf_attr *);

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

  printf("my_syscall triggered with sysno: %ld and cmd: %ld\n", __sysno, arg0);

  if (arg0 == 5) { // TODO: use BPF_PROG_LOAD enum instead of "5"
    printf("calling prog_load in harness...\n");
    bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t)); // TODO: correct?
    b->is_kernel = true;
    b->kernel = NULL;
    b->user = NULL;
    return (long int) test((union bpf_attr *)arg1, b, "spicy test");
  } else if (arg0 == 18) {
    printf("calling btf_load in harness...\n");
    // TODO
    bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t)); // TODO: correct?
    b->is_kernel = true;
    b->kernel = NULL;
    b->user = NULL;
    return (long int) bpf_btf_load((union bpf_attr *)arg1, *b);
  } else if (arg0 == 0) {
    printf("calling map_create in harness...\n");
    // TODO
    return (long int) map_create((union bpf_attr *)arg1);
  }

  return syscall(__sysno, arg0, arg1, arg2, arg3, arg4, arg5);
}
