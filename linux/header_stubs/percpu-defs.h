#include <linux/percpu-defs.h>

#undef this_cpu_inc
#define this_cpu_inc(pcp)

#undef this_cpu_dec
#define this_cpu_dec(pcp)
