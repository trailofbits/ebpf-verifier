#include <linux/percpu-defs.h>
#include <linux/cpumask.h>

#undef for_each_possible_cpu
#define for_each_possible_cpu(cpu) for(cpu = 0; cpu < 1; cpu++)

#undef per_cpu_ptr
#define per_cpu_ptr(ptr, cpu) ptr

#undef num_possible_cpus
#define num_possible_cpus() 1

#undef num_online_cpus
#define num_online_cpus() 1
