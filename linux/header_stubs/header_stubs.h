/*
Add this file to every kernel source file.
It manages which specific header_stubs should
be used for each of the files.
Within the header files themselves differences between
kernel versions are handled using ifdefs.
*/

/* Should be included for all kernel/bpf/...o files */

#include "slab.h"
#include "quirks.h"
#include "signal.h"

/* Most directly relevant files to verifier */
#ifdef KERNEL_BPF_SYSCALL
#include "atomics.h"
#include "current.h"
#include "sched.h"
#include "workqueue.h"
#include "sched_signal.h"
#include "lock.h"
#include "uaccess.h"

#include "preempt.h"
#include "percpu-defs.h"
#include "cred.h"
#include "current.h"
#include "file.h"
#include "sched_task.h"
#include "syscalls.h"

#endif /* kernel/bpf/syscall */

#ifdef KERNEL_BPF_VERIFIER
#include "mm.h"
#include "kernel.h"
#include "lock.h"
#include "uaccess.h"
#include "current.h"
#include "fs.h"
#include "sched_signal.h"
#include "file.h"
#endif /* kernel/bpf/verifier */

#ifdef KERNEL_BPF_BTF
#include "atomics.h"
#include "mm.h"
#include "lock.h"
#include "file.h"
#include "uaccess.h"
#include "preempt.h"
#include "refcount.h"
#endif /* kernel/bpf/btf */

/* Other kernel/bpf files */

#ifdef KERNEL_BPF_ARRAYMAP
#endif /* kernel/bpf/arraymap */

#ifdef KERNEL_BPF_BLOOM_FILTER
#endif /* kernel/bpf/bloom_filter */

#ifdef KERNEL_BPF_BPF_ITER
#endif /* kernel/bpf/bpf_iter */

#ifdef KERNEL_BPF_BPF_LOCAL_STORAGE
#endif /* kernel/bpf/bpf_local_storage */

#ifdef KERNEL_BPF_BPF_LRU_LIST
#endif /* kernel/bpf/bpf_lru_list */

#ifdef KERNEL_BPF_BPF_STRUCT_OPS
#endif /* kernel/bpf/bpf_struct_ops */

#ifdef KERNEL_BPF_BPF_TASK_STORAGE
#endif /* kernel/bpf/bpf_task_storage */

#ifdef KERNEL_BPF_CGROUP
#endif /* kernel/bpf/cgroup */

#ifdef KERNEL_BPF_CORE
#include "percpumask.h"
#endif /* kernel/bpf/core */

#ifdef KERNEL_BPF_CPUMAP
#endif /* kernel/bpf/cpumap */

#ifdef KERNEL_BPF_DEVMAP
#endif /* kernel/bpf/devmap */

#ifdef KERNEL_BPF_DISASM
#endif /* kernel/bpf/disasm */

#ifdef KERNEL_BPF_DISPATCHER
#endif /* kernel/bpf/dispatcher */

#ifdef KERNEL_BPF_HASHTAB
#include "percpumask.h"
#endif /* kernel/bpf/hashtab */

#ifdef KERNEL_BPF_HELPERS
#endif /* kernel/bpf/helpers */

#ifdef KERNEL_BPF_INODE
#endif /* kernel/bpf/inode */

#ifdef KERNEL_BPF_LOCAL_STORAGE
#endif /* kernel/bpf/local_storage */

#ifdef KERNEL_BPF_LPM_TRIE
#endif /* kernel/bpf/lpm_trie */

#ifdef KERNEL_BPF_MAP_IN_MAP
#include <linux/gfp.h>
#endif /* kernel/bpf/map_in_map */

#ifdef KERNEL_BPF_MAP_ITER
#endif /* kernel/bpf/map_iter */

#ifdef KERNEL_BPF_NET_NAMESPACE
#endif /* kernel/bpf/net_namespace */

#ifdef KERNEL_BPF_OFFLOAD
#endif /* kernel/bpf/offload */

#ifdef KERNEL_BPF_PERCPU_FREELIST
#include "percpumask.h"
#include "irqflags.h"
#include "smp.h"
#include "preempt.h"
#endif /* kernel/bpf/percpu_freelist */

#ifdef KERNEL_BPF_PROG_ITER
#endif /* kernel/bpf/prog_iter */

#ifdef KERNEL_BPF_QUEUE_STACK_MAPS
#endif /* kernel/bpf/queue_stack_maps */

#ifdef KERNEL_BPF_REUSEPORT_ARRAY
#endif /* kernel/bpf/reuseport_array */

#ifdef KERNEL_BPF_RINGBUF
#include "topology.h"
#include "mm_types.h"
#endif /* kernel/bpf/ringbuf */

#ifdef KERNEL_BPF_STACKMAP
#endif /* kernel/bpf/stackmap */

#ifdef KERNEL_BPF_SYSFS_BTF
#endif /* kernel/bpf/sysfs_btf */

#ifdef KERNEL_BPF_TASK_ITER
#endif /* kernel/bpf/task_iter */

#ifdef KERNEL_BPF_TNUM
#endif /* kernel/bpf/tnum */

#ifdef KERNEL_BPF_TRAMPOLINE
#endif /* kernel/bpf/trampoline */


#ifdef KERNEL_TRACE_BPF_TRACE
#endif /* kernel/trace/bpf_trace */

#ifdef KERNEL_KSYSFS
#endif /* kernel/ksysfs */



#ifdef NET_BPF_BPF_DUMMY_STRUCT_OPS
#endif /* net/bpf/bpf_dummy_struct_ops */

#ifdef NET_BPF_TEST_RUN
#endif /* net/bpf/test_run */

#ifdef NET_CORE_FILTER
#include "net_core_filter_wrapper.h"
#endif /* net/core/filter */

#ifdef NET_CORE_BPF_SK_STORAGE
#endif /* net/core/bpf_sk_storage */

#ifdef NET_CORE_SOCK_MAP
#endif /* net/core/sock_map */

#ifdef NET_IPV4_BPF_TCP_CA
#endif /* net/ipv4/bpf_tcp_ca */


#ifdef LIB_STRING
#endif /* lib/string */

#ifdef LIB_CTYPE
#endif /* lib/ctype */

#ifdef LIB_SHA1
#endif /* lib/sha1 */

#ifdef LIB_FIND_BIT
#endif /* lib/find_bit */

#ifdef LIB_SORT
#endif /* lib/sort */

#ifdef LIB_BITMAP
#endif /* lib/bitmap */

#ifdef LIB_HWEIGHT
#endif /* lib/hweight */

#ifdef LIB_CPUMASK
#endif /* lib/cpumask */


