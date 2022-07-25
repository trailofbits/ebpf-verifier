#include<sys/syscall.h>
#include <unistd.h>

inline long int __syscall (long int __sysno, ...) {
  if (__sysno == __NR_bpf) {
    // do my own thing
  } else {
    // pass on to regular handler
    //va list
  }
}

