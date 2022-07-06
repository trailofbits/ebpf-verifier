#include <stddef.h>
#include <stdlib.h>
#include <time.h>

// // Functions that look like they should only be called in the interpreter
// void bpf_map_write_active(void) { abort(); }

// // Unknown
// void refcount_warn_saturate(void) {abort(); } // TODO: what is this function
// void gic_nonsecure_priorities(void) {abort(); } // TODO: ^^^
// void queued_spin_lock_slowpath(void) { abort(); } // TODO

// void __alloc_percpu_gfp(void) { abort(); } // TODO --> autogened
// void __bpf_map_get(void) { abort(); } // TODO --> autogened
// void __cond_resched(void) { abort(); } // TODO --> autogened
// void __do_once_done(void) { abort(); } // TODO --> autogened
// void __do_once_start(void) { abort(); } // TODO --> autogened
// void __fdget(void) { abort(); } // TODO --> autogened
// void __local_bh_enable_ip(void) { abort(); } // TODO --> autogened
// void __mutex_init(void) { abort(); } // TODO --> autogened
// void __per_cpu_offset(void) { abort(); } // TODO --> autogened
// void __task_pid_nr_ns(void) { abort(); } // TODO --> autogened
// void _ctype(void) { abort(); } // TODO --> autogened
// void access_process_vm(void) { abort(); } // TODO --> autogened
// void anon_inode_getfd(void) { abort(); } // TODO --> autogened
// void array_map_ops(void) { abort(); } // TODO --> autogened
// void array_of_maps_map_ops(void) { abort(); } // TODO --> autogened
// void bloom_filter_map_ops(void) { abort(); } // TODO --> autogened
// void bpf_check_uarg_tail_zero(void) { abort(); } // TODO --> autogened
// void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
// void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
// void bpf_for_each_map_elem_proto(void) { abort(); } // TODO --> autogened
// void bpf_iter_prog_supported(void) { abort(); } // TODO --> autogened
// void bpf_loop_proto(void) { abort(); } // TODO --> autogened
// void bpf_map_inc(void) { abort(); } // TODO --> autogened
// void bpf_map_put(void) { abort(); } // TODO --> autogened
// void bpf_prog_inc_not_zero(void) { abort(); } // TODO --> autogened
// void bpf_prog_put(void) { abort(); } // TODO --> autogened
// void bpf_ringbuf_discard_proto(void) { abort(); } // TODO --> autogened
// void bpf_ringbuf_output_proto(void) { abort(); } // TODO --> autogened
// void bpf_ringbuf_query_proto(void) { abort(); } // TODO --> autogened
// void bpf_ringbuf_reserve_proto(void) { abort(); } // TODO --> autogened
// void bpf_ringbuf_submit_proto(void) { abort(); } // TODO --> autogened
// void bpf_syscall_verifier_ops(void) { abort(); } // TODO --> autogened
// void bstr_printf(void) { abort(); } // TODO --> autogened
// void call_rcu(void) { abort(); } // TODO --> autogened
// void cpu_number(void) { abort(); } // TODO --> autogened
// void find_vm_area(void) { abort(); } // TODO --> autogened
// void fput(void) { abort(); } // TODO --> autogened
// void free_percpu(void) { abort(); } // TODO --> autogened
// void get_random_u32(void) { abort(); } // TODO --> autogened
// void hrtimer_cancel(void) { abort(); } // TODO --> autogened
// void hrtimer_init(void) { abort(); } // TODO --> autogened
// void hrtimer_start_range_ns(void) { abort(); } // TODO --> autogened
// void htab_lru_map_ops(void) { abort(); } // TODO --> autogened
// void htab_lru_percpu_map_ops(void) { abort(); } // TODO --> autogened
// void htab_map_ops(void) { abort(); } // TODO --> autogened
// void htab_of_maps_map_ops(void) { abort(); } // TODO --> autogened
// void htab_percpu_map_ops(void) { abort(); } // TODO --> autogened
// void idr_alloc_cyclic(void) { abort(); } // TODO --> autogened
// void idr_find(void) { abort(); } // TODO --> autogened
// void idr_get_next(void) { abort(); } // TODO --> autogened
// void idr_preload(void) { abort(); } // TODO --> autogened
// void idr_remove(void) { abort(); } // TODO --> autogened
// void kmemdup(void) { abort(); } // TODO --> autogened
// void kmemdup_nul(void) { abort(); } // TODO --> autogened

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


// void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
// void mutex_lock(void) { abort(); } // TODO --> autogened
// void mutex_unlock(void) { abort(); } // TODO --> autogened
// void nr_cpu_ids(void) { abort(); } // TODO --> autogened
// void ns_match(void) { abort(); } // TODO --> autogened
// void percpu_array_map_ops(void) { abort(); } // TODO --> autogened
// void perf_event_array_map_ops(void) { abort(); } // TODO --> autogened
// void prandom_seed_full_state(void) { abort(); } // TODO --> autogened
// void prandom_u32_state(void) { abort(); } // TODO --> autogened
// void prog_array_map_ops(void) { abort(); } // TODO --> autogened
// void queue_map_ops(void) { abort(); } // TODO --> autogened
// void queue_work_on(void) { abort(); } // TODO --> autogened
// void ringbuf_map_ops(void) { abort(); } // TODO --> autogened
// void seq_vprintf(void) { abort(); } // TODO --> autogened
// void set_memory_ro(void) { abort(); } // TODO --> autogened
// void sha1_init(void) { abort(); } // TODO --> autogened
// void sha1_transform(void) { abort(); } // TODO --> autogened
// void sort(void) { abort(); } // TODO --> autogened
// void stack_map_ops(void) { abort(); } // TODO --> autogened
// void strnchr(void) { abort(); } // TODO --> autogened
// void strscpy(void) { abort(); } // TODO --> autogened
// void task_active_pid_ns(void) { abort(); } // TODO --> autogened
// void task_storage_map_ops(void) { abort(); } // TODO --> autogened
// void trie_map_ops(void) { abort(); } // TODO --> autogened
// void vmalloc(void) { abort(); } // TODO --> autogened
// void vscnprintf(void) { abort(); } // TODO --> autogened

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

void * __vmalloc(unsigned long size) { return malloc(size);}
void * vzalloc(unsigned long size) { return malloc(size); }

// TODO: these don't currently do anything
int krealloc(void *objp, size_t new_size) { return 1; }
int ksize(const void *objp) { return 1; }

void kfree(void *objp) { free(objp); }
void kvfree(void *addr) { free(addr); }
void vfree(void *addr) { free(addr); }

// additional ones found in 5.18.8 that didn't appear in 5.18.0 or whatever version
// I was working on before
// void __bitmap_clear(void) { abort(); } // TODO --> autogened
// void __bitmap_set(void) { abort(); } // TODO --> autogened
// void __rcu_read_lock(void) { abort(); } // TODO --> autogened
// void __rcu_read_unlock(void) { abort(); } // TODO --> autogened
// void __sw_hweight64(void) { abort(); } // TODO --> autogened
// void __warn_printk(void) { abort(); } // TODO --> autogened
// void _parse_integer(void) { abort(); } // TODO --> autogened
// void _parse_integer_fixup_radix(void) { abort(); } // TODO --> autogened
// void _printk(void) { abort(); } // TODO --> autogened
// void _raw_spin_lock(void) { abort(); } // TODO --> autogened
// void _raw_spin_lock_bh(void) { abort(); } // TODO --> autogened
// void _raw_spin_lock_irqsave(void) { abort(); } // TODO --> autogened
// void _raw_spin_unlock(void) { abort(); } // TODO --> autogened
// void _raw_spin_unlock_bh(void) { abort(); } // TODO --> autogened
// void _raw_spin_unlock_irqrestore(void) { abort(); } // TODO --> autogened
// void bin2hex(void) { abort(); } // TODO --> autogened
// void bitmap_find_next_zero_area_off(void) { abort(); } // TODO --> autogened
// void bpf_cgroup_storage_assign(void) { abort(); } // TODO --> autogened
// void bpf_extension_verifier_ops(void) { abort(); } // TODO --> autogened
// void bpf_map_kmalloc_node(void) { abort(); } // TODO --> autogened
// void bpf_map_offload_ops(void) { abort(); } // TODO --> autogened
// void bpf_offload_prog_map_match(void) { abort(); } // TODO --> autogened
// void bpf_prog_has_trampoline(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_compile(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_destroy(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_finalize(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_remove_insns(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_replace_insn(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_verifier_prep(void) { abort(); } // TODO --> autogened
// void bpf_prog_offload_verify_insn(void) { abort(); } // TODO --> autogened
// void bpf_sock_common_is_valid_access(void) { abort(); } // TODO --> autogened
// void bpf_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
// void bpf_sock_is_valid_access(void) { abort(); } // TODO --> autogened
// void bpf_struct_ops_find(void) { abort(); } // TODO --> autogened
// void bpf_struct_ops_init(void) { abort(); } // TODO --> autogened
// void bpf_struct_ops_map_ops(void) { abort(); } // TODO --> autogened
// void bpf_struct_ops_verifier_ops(void) { abort(); } // TODO --> autogened
// void bpf_tcp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
// void bpf_tcp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
// void bpf_trampoline_get(void) { abort(); } // TODO --> autogened
// void bpf_trampoline_put(void) { abort(); } // TODO --> autogened
// void bpf_xdp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
// void bpf_xdp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
// void btf_sock_ids(void) { abort(); } // TODO --> autogened
// void capable(void) { abort(); } // TODO --> autogened
// void cg_dev_verifier_ops(void) { abort(); } // TODO --> autogened
// void cg_skb_verifier_ops(void) { abort(); } // TODO --> autogened
// void cg_sock_addr_verifier_ops(void) { abort(); } // TODO --> autogened
// void cg_sock_verifier_ops(void) { abort(); } // TODO --> autogened
// void cg_sockopt_verifier_ops(void) { abort(); } // TODO --> autogened
// void cg_sysctl_verifier_ops(void) { abort(); } // TODO --> autogened
// void cgroup_array_map_ops(void) { abort(); } // TODO --> autogened
// void cgroup_storage_map_ops(void) { abort(); } // TODO --> autogened
// void cpu_hwcap_keys(void) { abort(); } // TODO --> autogened
// void cpu_map_ops(void) { abort(); } // TODO --> autogened
// void dev_map_hash_ops(void) { abort(); } // TODO --> autogened
// void dev_map_ops(void) { abort(); } // TODO --> autogened
// void flow_dissector_verifier_ops(void) { abort(); } // TODO --> autogened
// void from_kgid(void) { abort(); } // TODO --> autogened
// void from_kuid(void) { abort(); } // TODO --> autogened
// void get_callchain_buffers(void) { abort(); } // TODO --> autogened
// void init_user_ns(void) { abort(); } // TODO --> autogened
// void kallsyms_lookup_name(void) { abort(); } // TODO --> autogened
// void kmalloc_caches(void) { abort(); } // TODO --> autogened
// void kmem_cache_alloc(void) { abort(); } // TODO --> autogened
// void lwt_in_verifier_ops(void) { abort(); } // TODO --> autogened
// void lwt_out_verifier_ops(void) { abort(); } // TODO --> autogened
// void lwt_seg6local_verifier_ops(void) { abort(); } // TODO --> autogened
// void lwt_xmit_verifier_ops(void) { abort(); } // TODO --> autogened
// void module_alloc(void) { abort(); } // TODO --> autogened
// void module_memfree(void) { abort(); } // TODO --> autogened
// void module_put(void) { abort(); } // TODO --> autogened
// void node_states(void) { abort(); } // TODO --> autogened
// void numa_node(void) { abort(); } // TODO --> autogened
// void preempt_schedule(void) { abort(); } // TODO --> autogened
// void preempt_schedule_notrace(void) { abort(); } // TODO --> autogened
// void put_callchain_buffers(void) { abort(); } // TODO --> autogened
// void rb_erase(void) { abort(); } // TODO --> autogened
// void rb_insert_color(void) { abort(); } // TODO --> autogened
// void reuseport_array_ops(void) { abort(); } // TODO --> autogened
// void search_extable(void) { abort(); } // TODO --> autogened
// void security_locked_down(void) { abort(); } // TODO --> autogened
// void seq_printf(void) { abort(); } // TODO --> autogened
// void set_memory_x(void) { abort(); } // TODO --> autogened
// void sk_filter_verifier_ops(void) { abort(); } // TODO --> autogened
// void sk_lookup_verifier_ops(void) { abort(); } // TODO --> autogened
// void sk_msg_verifier_ops(void) { abort(); } // TODO --> autogened
// void sk_reuseport_verifier_ops(void) { abort(); } // TODO --> autogened
// void sk_skb_verifier_ops(void) { abort(); } // TODO --> autogened
// void sk_storage_map_ops(void) { abort(); } // TODO --> autogened
// void sock_hash_ops(void) { abort(); } // TODO --> autogened
// void sock_map_ops(void) { abort(); } // TODO --> autogened
// void sock_ops_verifier_ops(void) { abort(); } // TODO --> autogened
// void stack_trace_map_ops(void) { abort(); } // TODO --> autogened
// void sysctl_perf_event_max_stack(void) { abort(); } // TODO --> autogened
// void tc_cls_act_verifier_ops(void) { abort(); } // TODO --> autogened
// void xdp_verifier_ops(void) { abort(); } // TODO --> autogened
void __alloc_percpu_gfp(void) { abort(); } // TODO --> autogened
void __bitmap_clear(void) { abort(); } // TODO --> autogened
void __bitmap_set(void) { abort(); } // TODO --> autogened
void __bpf_map_get(void) { abort(); } // TODO --> autogened
void __do_once_done(void) { abort(); } // TODO --> autogened
void __do_once_start(void) { abort(); } // TODO --> autogened
void __fdget(void) { abort(); } // TODO --> autogened
void __mutex_init(void) { abort(); } // TODO --> autogened
void __per_cpu_offset(void) { abort(); } // TODO --> autogened
void __rcu_read_lock(void) { abort(); } // TODO --> autogened
void __rcu_read_unlock(void) { abort(); } // TODO --> autogened
void __sw_hweight64(void) { abort(); } // TODO --> autogened
void __task_pid_nr_ns(void) { abort(); } // TODO --> autogened
void __warn_printk(void) { abort(); } // TODO --> autogened
void _ctype(void) { abort(); } // TODO --> autogened
void _parse_integer(void) { abort(); } // TODO --> autogened
void _parse_integer_fixup_radix(void) { abort(); } // TODO --> autogened
void _printk(void) { abort(); } // TODO --> autogened
void _raw_spin_lock(void) { abort(); } // TODO --> autogened
void _raw_spin_lock_bh(void) { abort(); } // TODO --> autogened
void _raw_spin_lock_irqsave(void) { abort(); } // TODO --> autogened
void _raw_spin_unlock(void) { abort(); } // TODO --> autogened
void _raw_spin_unlock_bh(void) { abort(); } // TODO --> autogened
void _raw_spin_unlock_irqrestore(void) { abort(); } // TODO --> autogened
void access_process_vm(void) { abort(); } // TODO --> autogened
void anon_inode_getfd(void) { abort(); } // TODO --> autogened
void array_map_ops(void) { abort(); } // TODO --> autogened
void array_of_maps_map_ops(void) { abort(); } // TODO --> autogened
void bin2hex(void) { abort(); } // TODO --> autogened
void bitmap_find_next_zero_area_off(void) { abort(); } // TODO --> autogened
void bloom_filter_map_ops(void) { abort(); } // TODO --> autogened
void bpf_cgroup_storage_assign(void) { abort(); } // TODO --> autogened
void bpf_check_uarg_tail_zero(void) { abort(); } // TODO --> autogened
void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
void bpf_extension_verifier_ops(void) { abort(); } // TODO --> autogened
void bpf_for_each_map_elem_proto(void) { abort(); } // TODO --> autogened
void bpf_iter_prog_supported(void) { abort(); } // TODO --> autogened
void bpf_loop_proto(void) { abort(); } // TODO --> autogened
void bpf_map_inc(void) { abort(); } // TODO --> autogened
void bpf_map_kmalloc_node(void) { abort(); } // TODO --> autogened
void bpf_map_offload_ops(void) { abort(); } // TODO --> autogened
void bpf_map_put(void) { abort(); } // TODO --> autogened
void bpf_map_write_active(void) { abort(); } // TODO --> autogened
void bpf_offload_prog_map_match(void) { abort(); } // TODO --> autogened
void bpf_prog_has_trampoline(void) { abort(); } // TODO --> autogened
void bpf_prog_inc_not_zero(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_compile(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_destroy(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_finalize(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_remove_insns(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_replace_insn(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verifier_prep(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verify_insn(void) { abort(); } // TODO --> autogened
void bpf_prog_put(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_discard_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_output_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_query_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_reserve_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_submit_proto(void) { abort(); } // TODO --> autogened
void bpf_sock_common_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_find(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_init(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_map_ops(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_verifier_ops(void) { abort(); } // TODO --> autogened
void bpf_syscall_verifier_ops(void) { abort(); } // TODO --> autogened
void bpf_tcp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_tcp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_trampoline_get(void) { abort(); } // TODO --> autogened
void bpf_trampoline_put(void) { abort(); } // TODO --> autogened
void bpf_xdp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_xdp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void bstr_printf(void) { abort(); } // TODO --> autogened
void btf_sock_ids(void) { abort(); } // TODO --> autogened
void call_rcu(void) { abort(); } // TODO --> autogened
void capable(void) { abort(); } // TODO --> autogened
void cg_dev_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_skb_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sock_addr_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sock_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sockopt_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sysctl_verifier_ops(void) { abort(); } // TODO --> autogened
void cgroup_array_map_ops(void) { abort(); } // TODO --> autogened
void cgroup_storage_map_ops(void) { abort(); } // TODO --> autogened
void cpu_hwcap_keys(void) { abort(); } // TODO --> autogened
void cpu_map_ops(void) { abort(); } // TODO --> autogened
void cpu_number(void) { abort(); } // TODO --> autogened
void dev_map_hash_ops(void) { abort(); } // TODO --> autogened
void dev_map_ops(void) { abort(); } // TODO --> autogened
void find_vm_area(void) { abort(); } // TODO --> autogened
void flow_dissector_verifier_ops(void) { abort(); } // TODO --> autogened
void fput(void) { abort(); } // TODO --> autogened
void free_percpu(void) { abort(); } // TODO --> autogened
void from_kgid(void) { abort(); } // TODO --> autogened
void from_kuid(void) { abort(); } // TODO --> autogened
void get_callchain_buffers(void) { abort(); } // TODO --> autogened
void get_random_u32(void) { abort(); } // TODO --> autogened
void gic_nonsecure_priorities(void) { abort(); } // TODO --> autogened
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
void init_user_ns(void) { abort(); } // TODO --> autogened
void kallsyms_lookup_name(void) { abort(); } // TODO --> autogened
void kmalloc_caches(void) { abort(); } // TODO --> autogened
void kmem_cache_alloc(void) { abort(); } // TODO --> autogened
void kmemdup(void) { abort(); } // TODO --> autogened
void kmemdup_nul(void) { abort(); } // TODO --> autogened
void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
void lwt_in_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_out_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_seg6local_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_xmit_verifier_ops(void) { abort(); } // TODO --> autogened
void module_alloc(void) { abort(); } // TODO --> autogened
void module_memfree(void) { abort(); } // TODO --> autogened
void module_put(void) { abort(); } // TODO --> autogened
void mutex_lock(void) { abort(); } // TODO --> autogened
void mutex_unlock(void) { abort(); } // TODO --> autogened
void node_states(void) { abort(); } // TODO --> autogened
void nr_cpu_ids(void) { abort(); } // TODO --> autogened
void ns_match(void) { abort(); } // TODO --> autogened
void numa_node(void) { abort(); } // TODO --> autogened
void percpu_array_map_ops(void) { abort(); } // TODO --> autogened
void perf_event_array_map_ops(void) { abort(); } // TODO --> autogened
void prandom_seed_full_state(void) { abort(); } // TODO --> autogened
void prandom_u32_state(void) { abort(); } // TODO --> autogened
void preempt_schedule(void) { abort(); } // TODO --> autogened
void preempt_schedule_notrace(void) { abort(); } // TODO --> autogened
void prog_array_map_ops(void) { abort(); } // TODO --> autogened
void put_callchain_buffers(void) { abort(); } // TODO --> autogened
void queue_map_ops(void) { abort(); } // TODO --> autogened
void queue_work_on(void) { abort(); } // TODO --> autogened
void queued_spin_lock_slowpath(void) { abort(); } // TODO --> autogened
void rb_erase(void) { abort(); } // TODO --> autogened
void rb_insert_color(void) { abort(); } // TODO --> autogened
void refcount_warn_saturate(void) { abort(); } // TODO --> autogened
void reuseport_array_ops(void) { abort(); } // TODO --> autogened
void ringbuf_map_ops(void) { abort(); } // TODO --> autogened
void search_extable(void) { abort(); } // TODO --> autogened
void security_locked_down(void) { abort(); } // TODO --> autogened
void seq_printf(void) { abort(); } // TODO --> autogened
void seq_vprintf(void) { abort(); } // TODO --> autogened
void set_memory_ro(void) { abort(); } // TODO --> autogened
void set_memory_x(void) { abort(); } // TODO --> autogened
void sha1_init(void) { abort(); } // TODO --> autogened
void sha1_transform(void) { abort(); } // TODO --> autogened
void sk_filter_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_lookup_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_msg_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_reuseport_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_skb_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_storage_map_ops(void) { abort(); } // TODO --> autogened
void sock_hash_ops(void) { abort(); } // TODO --> autogened
void sock_map_ops(void) { abort(); } // TODO --> autogened
void sock_ops_verifier_ops(void) { abort(); } // TODO --> autogened
void sort(void) { abort(); } // TODO --> autogened
void stack_map_ops(void) { abort(); } // TODO --> autogened
void stack_trace_map_ops(void) { abort(); } // TODO --> autogened
void strnchr(void) { abort(); } // TODO --> autogened
void strscpy(void) { abort(); } // TODO --> autogened
void sysctl_perf_event_max_stack(void) { abort(); } // TODO --> autogened
void task_active_pid_ns(void) { abort(); } // TODO --> autogened
void task_storage_map_ops(void) { abort(); } // TODO --> autogened
void tc_cls_act_verifier_ops(void) { abort(); } // TODO --> autogened
void trie_map_ops(void) { abort(); } // TODO --> autogened
void vmalloc(void) { abort(); } // TODO --> autogened
void vscnprintf(void) { abort(); } // TODO --> autogened
void xdp_verifier_ops(void) { abort(); } // TODO --> autogened
