#include <linux/percpu-defs.h>

#undef this_cpu_ptr
#define this_cpu_ptr(ptr) ptr
