#include <stddef.h>
#include <stdlib.h>
#include <time.h>

// Functions that look like they should only be called in the interpreter
void bpf_map_write_active(void) { abort(); }

// Unknown
void refcount_warn_saturate(void) {abort(); } // TODO: what is this function
void gic_nonsecure_priorities(void) {abort(); } // TODO: ^^^
void queued_spin_lock_slowpath(void) { abort(); } // TODO

void __alloc_percpu_gfp(void) { abort(); } // TODO --> autogened
void __bpf_map_get(void) { abort(); } // TODO --> autogened
void __cond_resched(void) { abort(); } // TODO --> autogened
void __do_once_done(void) { abort(); } // TODO --> autogened
void __do_once_start(void) { abort(); } // TODO --> autogened
void __fdget(void) { abort(); } // TODO --> autogened
void __local_bh_enable_ip(void) { abort(); } // TODO --> autogened
void __mutex_init(void) { abort(); } // TODO --> autogened
void __per_cpu_offset(void) { abort(); } // TODO --> autogened
void __task_pid_nr_ns(void) { abort(); } // TODO --> autogened
void _ctype(void) { abort(); } // TODO --> autogened
void access_process_vm(void) { abort(); } // TODO --> autogened
void anon_inode_getfd(void) { abort(); } // TODO --> autogened
void array_map_ops(void) { abort(); } // TODO --> autogened
void array_of_maps_map_ops(void) { abort(); } // TODO --> autogened
void bloom_filter_map_ops(void) { abort(); } // TODO --> autogened
void bpf_check_uarg_tail_zero(void) { abort(); } // TODO --> autogened
void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
void bpf_for_each_map_elem_proto(void) { abort(); } // TODO --> autogened
void bpf_iter_prog_supported(void) { abort(); } // TODO --> autogened
void bpf_loop_proto(void) { abort(); } // TODO --> autogened
void bpf_map_inc(void) { abort(); } // TODO --> autogened
void bpf_map_put(void) { abort(); } // TODO --> autogened
void bpf_prog_inc_not_zero(void) { abort(); } // TODO --> autogened
void bpf_prog_put(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_discard_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_output_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_query_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_reserve_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_submit_proto(void) { abort(); } // TODO --> autogened
void bpf_syscall_verifier_ops(void) { abort(); } // TODO --> autogened
void bstr_printf(void) { abort(); } // TODO --> autogened
void call_rcu(void) { abort(); } // TODO --> autogened
void cpu_number(void) { abort(); } // TODO --> autogened
void find_vm_area(void) { abort(); } // TODO --> autogened
void fput(void) { abort(); } // TODO --> autogened
void free_percpu(void) { abort(); } // TODO --> autogened
void get_random_u32(void) { abort(); } // TODO --> autogened
void hrtimer_cancel(void) { abort(); } // TODO --> autogened
void hrtimer_init(void) { abort(); } // TODO --> autogened
void hrtimer_start_range_ns(void) { abort(); } // TODO --> autogened
void htab_lru_map_ops(void) { abort(); } // TODO --> autogened
void htab_lru_percpu_map_ops(void) { abort(); } // TODO --> autogened
void htab_map_ops(void) { abort(); } // TODO --> autogened
void htab_of_maps_map_ops(void) { abort(); } // TODO --> autogened
void htab_percpu_map_ops(void) { abort(); } // TODO --> autogened
void idr_alloc_cyclic(void) { abort(); } // TODO --> autogened
void idr_find(void) { abort(); } // TODO --> autogened
void idr_get_next(void) { abort(); } // TODO --> autogened
void idr_preload(void) { abort(); } // TODO --> autogened
void idr_remove(void) { abort(); } // TODO --> autogened
void kmemdup(void) { abort(); } // TODO --> autogened
void kmemdup_nul(void) { abort(); } // TODO --> autogened

// ktime accessors

// I only see this called twice in bpf_check --> just seems to be timing the
// verifier process.
unsigned long ktime_get(void) {
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec;
}

void ktime_get_boot_fast_ns(void) { abort(); } // TODO --> autogened
void ktime_get_coarse_ts64(void) { abort(); } // TODO --> autogened
void ktime_get_mono_fast_ns(void) { abort(); } // TODO --> autogened


void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
void mutex_lock(void) { abort(); } // TODO --> autogened
void mutex_unlock(void) { abort(); } // TODO --> autogened
void nr_cpu_ids(void) { abort(); } // TODO --> autogened
void ns_match(void) { abort(); } // TODO --> autogened
void percpu_array_map_ops(void) { abort(); } // TODO --> autogened
void perf_event_array_map_ops(void) { abort(); } // TODO --> autogened
void prandom_seed_full_state(void) { abort(); } // TODO --> autogened
void prandom_u32_state(void) { abort(); } // TODO --> autogened
void prog_array_map_ops(void) { abort(); } // TODO --> autogened
void queue_map_ops(void) { abort(); } // TODO --> autogened
void queue_work_on(void) { abort(); } // TODO --> autogened
void ringbuf_map_ops(void) { abort(); } // TODO --> autogened
void seq_vprintf(void) { abort(); } // TODO --> autogened
void set_memory_ro(void) { abort(); } // TODO --> autogened
void sha1_init(void) { abort(); } // TODO --> autogened
void sha1_transform(void) { abort(); } // TODO --> autogened
void sort(void) { abort(); } // TODO --> autogened
void stack_map_ops(void) { abort(); } // TODO --> autogened
void strnchr(void) { abort(); } // TODO --> autogened
void strscpy(void) { abort(); } // TODO --> autogened
void task_active_pid_ns(void) { abort(); } // TODO --> autogened
void task_storage_map_ops(void) { abort(); } // TODO --> autogened
void trie_map_ops(void) { abort(); } // TODO --> autogened
void vmalloc(void) { abort(); } // TODO --> autogened
void vscnprintf(void) { abort(); } // TODO --> autogened

unsigned long			vabits_actual = 64;  // TODO
void *  system_wq = NULL; // TODO
unsigned long jiffies = 1; // TODO


int pagefault_disable() { return 1; }

// Memory related functions.
// TODO: look at intricacies of the different alloc functions and
// either change them to be different below or reduce redundancy of this code
void * kmalloc (size_t size) {
  void * x = malloc(size);
  return __builtin_memset(x, 0, size);
}
void * __kmalloc (size_t size) {
  void * x = malloc(size);
  return __builtin_memset(x, 0, size);
}
void * kmalloc_order(size_t size, int flags, unsigned int order) {
  void * x = malloc(size);
  return __builtin_memset(x, 0, size);
}
void * kvmalloc_node(size_t size) {
  void * x = malloc(size);
  return __builtin_memset(x, 0, size);
}

void *  __kmalloc_track_caller(size_t size) {
  void * x = malloc(size);
  return __builtin_memset(x, 0, size);
}

int kfree(const void *objp) { return 1; }
int krealloc(const void *objp, size_t new_size) { return 1; }
int ksize(const void *objp) { return 1; }
int kvfree(const void *addr) { return 1; }
int vfree(const void *addr) { return 1; }
void * __vmalloc(unsigned long size) { return malloc(size);}
void * vzalloc(unsigned long size) { return malloc(size); }
