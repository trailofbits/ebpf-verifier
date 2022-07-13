#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>


// stubbed out (decl as extern in "slab.h")
void * kzalloc(size_t size) { return malloc(size); }
void * kvcalloc(size_t n, size_t size) { return calloc(n, size); }

void * __vmalloc(unsigned long size) { return malloc(size); } // TODO --> autogened

void * vzalloc(size_t size) { return malloc(size);  } // TODO --> autogened
void vfree(void *ptr) { free(ptr); } // TODO --> autogened
void kfree(void *ptr) { free(ptr); } // TODO --> autogened

void kmalloc(void) { abort(); }
void kvmalloc(void) { abort(); }
void kcalloc(void) { abort(); }
void kmalloc_array(void) { abort(); }
void krealloc_array(void) { abort(); }
void kmalloc_node(void) { abort(); }


// // I only see this called twice in bpf_check --> just seems to be timing the
// // verifier process.
unsigned long ktime_get(void) {
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec;
}

bool capable(int cap) { return true; } // always true for test harness

void * __alloc_percpu_gfp(size_t size, size_t align) { return malloc(size); } // TODO --> autogened
void __mutex_init(void) { return; } // TODO --> autogened
int security_bpf_prog_alloc(struct bpf_prog_aux *aux) { return 0; } // TODO --> autogened

struct user_struct *get_current_user() { return NULL; }
void current_uid_gid(int *uid, int *gid) { abort(); }
void current_cred(void) { abort(); }

void free_uid(struct user_struct *) { return; } // TODO --> autogened
void security_bpf_prog_free(struct bpf_prog_aux *) { return; } // TODO --> autogened

void _find_next_bit(void) { abort(); }


void __bitmap_clear(void) { abort(); } // TODO --> autogened
void __bitmap_set(void) { abort(); } // TODO --> autogened
void __bitmap_weight(void) { abort(); } // TODO --> autogened
void __bpf_prog_enter_sleepable(void) { abort(); } // TODO --> autogened
void __bpf_prog_exit_sleepable(void) { abort(); } // TODO --> autogened
void __cpu_possible_mask(void) { abort(); } // TODO --> autogened
void __do_once_done(void) { abort(); } // TODO --> autogened
void __do_once_start(void) { abort(); } // TODO --> autogened
void __fdget(void) { abort(); } // TODO --> autogened
void __kmalloc(void) { abort(); } // TODO --> autogened
void __kmalloc_node(void) { abort(); } // TODO --> autogened

void __per_cpu_offset(void) { abort(); } // TODO --> autogened
void __put_task_struct(void) { abort(); } // TODO --> autogened
void __rcu_read_lock(void) { abort(); } // TODO --> autogened
void __rcu_read_unlock(void) { abort(); } // TODO --> autogened
void __sw_hweight64(void) { abort(); } // TODO --> autogened
//void __sys_bpf(void) { abort(); } // TODO --> autogened
void __task_pid_nr_ns(void) { abort(); } // TODO --> autogened

void __vmalloc_node_range(void) { abort(); } // TODO --> autogened
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
void anon_inode_getfile(void) { abort(); } // TODO --> autogened
void arm64_use_ng_mappings(void) { abort(); } // TODO --> autogened
void array_map_ops(void) { abort(); } // TODO --> autogened
void array_of_maps_map_ops(void) { abort(); } // TODO --> autogened
void audit_enabled(void) { abort(); } // TODO --> autogened
void audit_log_end(void) { abort(); } // TODO --> autogened
void audit_log_format(void) { abort(); } // TODO --> autogened
void audit_log_start(void) { abort(); } // TODO --> autogened
void bin2hex(void) { abort(); } // TODO --> autogened
void bitmap_find_next_zero_area_off(void) { abort(); } // TODO --> autogened
void bloom_filter_map_ops(void) { abort(); } // TODO --> autogened
void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
void bpf_extension_prog_ops(void) { abort(); } // TODO --> autogened
void bpf_extension_verifier_ops(void) { abort(); } // TODO --> autogened
void bpf_fd_array_map_lookup_elem(void) { abort(); } // TODO --> autogened
void bpf_fd_array_map_update_elem(void) { abort(); } // TODO --> autogened
void bpf_fd_htab_map_lookup_elem(void) { abort(); } // TODO --> autogened
void bpf_fd_htab_map_update_elem(void) { abort(); } // TODO --> autogened
void bpf_fd_reuseport_array_lookup_elem(void) { abort(); } // TODO --> autogened
void bpf_fd_reuseport_array_update_elem(void) { abort(); } // TODO --> autogened
void bpf_for_each_map_elem_proto(void) { abort(); } // TODO --> autogened
void bpf_iter_link_attach(void) { abort(); } // TODO --> autogened
void bpf_iter_new_fd(void) { abort(); } // TODO --> autogened
void bpf_loop_proto(void) { abort(); } // TODO --> autogened
void bpf_map_meta_equal(void) { abort(); } // TODO --> autogened
void bpf_map_offload_delete_elem(void) { abort(); } // TODO --> autogened
void bpf_map_offload_get_next_key(void) { abort(); } // TODO --> autogened
void bpf_map_offload_info_fill(void) { abort(); } // TODO --> autogened
void bpf_map_offload_lookup_elem(void) { abort(); } // TODO --> autogened
void bpf_map_offload_map_alloc(void) { abort(); } // TODO --> autogened
void bpf_map_offload_map_free(void) { abort(); } // TODO --> autogened
void bpf_map_offload_update_elem(void) { abort(); } // TODO --> autogened
void bpf_obj_get_user(void) { abort(); } // TODO --> autogened
void bpf_obj_pin_user(void) { abort(); } // TODO --> autogened
void bpf_offload_prog_ops(void) { abort(); } // TODO --> autogened
void bpf_percpu_array_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_array_update(void) { abort(); } // TODO --> autogened
void bpf_percpu_cgroup_storage_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_cgroup_storage_update(void) { abort(); } // TODO --> autogened
void bpf_percpu_hash_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_hash_update(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_compile(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_destroy(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_info_fill(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_init(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_syscall(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_discard_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_output_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_query_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_reserve_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_submit_proto(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_init(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_map_ops(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_map_sys_lookup_elem(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_prog_ops(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_verifier_ops(void) { abort(); } // TODO --> autogened
void bpf_trampoline_get(void) { abort(); } // TODO --> autogened
void bpf_trampoline_link_prog(void) { abort(); } // TODO --> autogened
void bpf_trampoline_put(void) { abort(); } // TODO --> autogened
void bpf_trampoline_unlink_prog(void) { abort(); } // TODO --> autogened
void bpf_xdp_link_attach(void) { abort(); } // TODO --> autogened
void bstr_printf(void) { abort(); } // TODO --> autogened
void btf_sock_ids(void) { abort(); } // TODO --> autogened
void call_rcu(void) { abort(); } // TODO --> autogened
void call_rcu_tasks_trace(void) { abort(); } // TODO --> autogened

void cg_dev_prog_ops(void) { abort(); } // TODO --> autogened
void cg_dev_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_skb_prog_ops(void) { abort(); } // TODO --> autogened
void cg_skb_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sock_addr_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sock_addr_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sock_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sock_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sockopt_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sockopt_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sysctl_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sysctl_verifier_ops(void) { abort(); } // TODO --> autogened
void cgroup_array_map_ops(void) { abort(); } // TODO --> autogened
void cgroup_bpf_link_attach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_attach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_detach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_query(void) { abort(); } // TODO --> autogened
void cgroup_storage_map_ops(void) { abort(); } // TODO --> autogened
void check_zeroed_user(void) { abort(); } // TODO --> autogened
void close_fd(void) { abort(); } // TODO --> autogened
void cpu_hwcap_keys(void) { abort(); } // TODO --> autogened
void cpu_map_ops(void) { abort(); } // TODO --> autogened
void cpu_number(void) { abort(); } // TODO --> autogened
void cpumask_next(void) { abort(); } // TODO --> autogened
void dev_map_hash_ops(void) { abort(); } // TODO --> autogened
void dev_map_ops(void) { abort(); } // TODO --> autogened
void fd_install(void) { abort(); } // TODO --> autogened
void fget_task(void) { abort(); } // TODO --> autogened
void find_vm_area(void) { abort(); } // TODO --> autogened
void find_vpid(void) { abort(); } // TODO --> autogened
void flow_dissector_prog_ops(void) { abort(); } // TODO --> autogened
void flow_dissector_verifier_ops(void) { abort(); } // TODO --> autogened
void fput(void) { abort(); } // TODO --> autogened
void free_percpu(void) { abort(); } // TODO --> autogened

void from_kgid(void) { abort(); } // TODO --> autogened
void from_kuid(void) { abort(); } // TODO --> autogened
void from_kuid_munged(void) { abort(); } // TODO --> autogened
void get_mem_cgroup_from_mm(void) { abort(); } // TODO --> autogened
void get_pid_task(void) { abort(); } // TODO --> autogened
void get_random_u32(void) { abort(); } // TODO --> autogened
void get_unused_fd_flags(void) { abort(); } // TODO --> autogened
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
void int_active_memcg(void) { abort(); } // TODO --> autogened
void jiffies(void) { abort(); } // TODO --> autogened
void kallsyms_lookup_name(void) { abort(); } // TODO --> autogened
void kallsyms_show_value(void) { abort(); } // TODO --> autogened
void kmalloc_caches(void) { abort(); } // TODO --> autogened
void kmem_cache_alloc(void) { abort(); } // TODO --> autogened
void kmemdup(void) { abort(); } // TODO --> autogened
void kmemdup_nul(void) { abort(); } // TODO --> autogened
void krealloc(void) { abort(); } // TODO --> autogened
void ktime_get_boot_fast_ns(void) { abort(); } // TODO --> autogened
void ktime_get_coarse_ts64(void) { abort(); } // TODO --> autogened
void ktime_get_mono_fast_ns(void) { abort(); } // TODO --> autogened
void ktime_get_with_offset(void) { abort(); } // TODO --> autogened
void kvfree(void) { abort(); } // TODO --> autogened
void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
void kvmalloc_node(void) { abort(); } // TODO --> autogened
void lwt_in_prog_ops(void) { abort(); } // TODO --> autogened
void lwt_in_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_out_prog_ops(void) { abort(); } // TODO --> autogened
void lwt_out_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_seg6local_prog_ops(void) { abort(); } // TODO --> autogened
void lwt_seg6local_verifier_ops(void) { abort(); } // TODO --> autogened
void lwt_xmit_prog_ops(void) { abort(); } // TODO --> autogened
void lwt_xmit_verifier_ops(void) { abort(); } // TODO --> autogened

void migrate_disable(void) { abort(); } // TODO --> autogened
void migrate_enable(void) { abort(); } // TODO --> autogened
void module_alloc(void) { abort(); } // TODO --> autogened
void module_memfree(void) { abort(); } // TODO --> autogened
void module_put(void) { abort(); } // TODO --> autogened
void mutex_lock(void) { abort(); } // TODO --> autogened
void mutex_unlock(void) { abort(); } // TODO --> autogened
void netns_bpf_link_create(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_attach(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_detach(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_query(void) { abort(); } // TODO --> autogened
void node_states(void) { abort(); } // TODO --> autogened
void nr_cpu_ids(void) { abort(); } // TODO --> autogened
void nr_node_ids(void) { abort(); } // TODO --> autogened
void ns_match(void) { abort(); } // TODO --> autogened
void numa_node(void) { abort(); } // TODO --> autogened
void percpu_array_map_ops(void) { abort(); } // TODO --> autogened
void perf_event_array_map_ops(void) { abort(); } // TODO --> autogened
void perf_event_bpf_event(void) { abort(); } // TODO --> autogened
void perf_event_free_bpf_prog(void) { abort(); } // TODO --> autogened
void perf_event_get(void) { abort(); } // TODO --> autogened
void perf_event_set_bpf_prog(void) { abort(); } // TODO --> autogened
void perf_get_event(void) { abort(); } // TODO --> autogened
void prandom_seed_full_state(void) { abort(); } // TODO --> autogened
void prandom_u32_state(void) { abort(); } // TODO --> autogened
void preempt_schedule(void) { abort(); } // TODO --> autogened
void preempt_schedule_notrace(void) { abort(); } // TODO --> autogened
void prog_array_map_ops(void) { abort(); } // TODO --> autogened
void put_callchain_buffers(void) { abort(); } // TODO --> autogened
void put_unused_fd(void) { abort(); } // TODO --> autogened
void queue_map_ops(void) { abort(); } // TODO --> autogened
void queue_work_on(void) { abort(); } // TODO --> autogened
void queued_spin_lock_slowpath(void) { abort(); } // TODO --> autogened
void rb_erase(void) { abort(); } // TODO --> autogened
void rb_insert_color(void) { abort(); } // TODO --> autogened
void refcount_warn_saturate(void) { abort(); } // TODO --> autogened
void reuseport_array_ops(void) { abort(); } // TODO --> autogened
void ringbuf_map_ops(void) { abort(); } // TODO --> autogened
void sched_clock(void) { abort(); } // TODO --> autogened
void search_extable(void) { abort(); } // TODO --> autogened
void security_bpf(void) { abort(); } // TODO --> autogened
void security_bpf_map(void) { abort(); } // TODO --> autogened
void security_bpf_map_alloc(void) { abort(); } // TODO --> autogened
void security_bpf_map_free(void) { abort(); } // TODO --> autogened
void security_bpf_prog(void) { abort(); } // TODO --> autogened


void security_locked_down(void) { abort(); } // TODO --> autogened
void seq_printf(void) { abort(); } // TODO --> autogened
void seq_vprintf(void) { abort(); } // TODO --> autogened
void set_memory_ro(void) { abort(); } // TODO --> autogened
void set_memory_x(void) { abort(); } // TODO --> autogened
void sha1_init(void) { abort(); } // TODO --> autogened
void sha1_transform(void) { abort(); } // TODO --> autogened
void sk_filter_prog_ops(void) { abort(); } // TODO --> autogened
void sk_filter_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_lookup_prog_ops(void) { abort(); } // TODO --> autogened
void sk_lookup_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_msg_prog_ops(void) { abort(); } // TODO --> autogened
void sk_msg_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_reuseport_prog_ops(void) { abort(); } // TODO --> autogened
void sk_reuseport_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_skb_prog_ops(void) { abort(); } // TODO --> autogened
void sk_skb_verifier_ops(void) { abort(); } // TODO --> autogened
void sk_storage_map_ops(void) { abort(); } // TODO --> autogened
void sock_hash_ops(void) { abort(); } // TODO --> autogened
void sock_map_bpf_prog_query(void) { abort(); } // TODO --> autogened
void sock_map_get_from_fd(void) { abort(); } // TODO --> autogened
void sock_map_ops(void) { abort(); } // TODO --> autogened
void sock_map_prog_detach(void) { abort(); } // TODO --> autogened
void sock_map_update_elem_sys(void) { abort(); } // TODO --> autogened
void sock_ops_prog_ops(void) { abort(); } // TODO --> autogened
void sock_ops_verifier_ops(void) { abort(); } // TODO --> autogened
void sort(void) { abort(); } // TODO --> autogened
void stack_map_ops(void) { abort(); } // TODO --> autogened
void stack_trace_map_ops(void) { abort(); } // TODO --> autogened
void static_key_count(void) { abort(); } // TODO --> autogened
void static_key_slow_dec(void) { abort(); } // TODO --> autogened
void static_key_slow_inc(void) { abort(); } // TODO --> autogened

void synchronize_rcu(void) { abort(); } // TODO --> autogened
void system_wq(void) { abort(); } // TODO --> autogened
void task_active_pid_ns(void) { abort(); } // TODO --> autogened
void task_storage_map_ops(void) { abort(); } // TODO --> autogened
void tc_cls_act_prog_ops(void) { abort(); } // TODO --> autogened
void tc_cls_act_verifier_ops(void) { abort(); } // TODO --> autogened
void trie_map_ops(void) { abort(); } // TODO --> autogened
void vabits_actual(void) { abort(); } // TODO --> autogened
void vmalloc(void) { abort(); } // TODO --> autogened
void vmemdup_user(void) { abort(); } // TODO --> autogened
void vscnprintf(void) { abort(); } // TODO --> autogened
void xdp_prog_ops(void) { abort(); } // TODO --> autogened
void xdp_verifier_ops(void) { abort(); } // TODO --> autogened

void __kmalloc_track_caller(void) { abort(); } // TODO --> autogened
void bpf_cgroup_storage_assign(void) { abort(); } // TODO --> autogened
void bpf_iter_prog_supported(void) { abort(); } // TODO --> autogened
void bpf_offload_prog_map_match(void) { abort(); } // TODO --> autogened
void bpf_prog_has_trampoline(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_finalize(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_remove_insns(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_replace_insn(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verifier_prep(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verify_insn(void) { abort(); } // TODO --> autogened
void bpf_sock_common_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_find(void) { abort(); } // TODO --> autogened
void bpf_tcp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_tcp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void bpf_xdp_sock_convert_ctx_access(void) { abort(); } // TODO --> autogened
void bpf_xdp_sock_is_valid_access(void) { abort(); } // TODO --> autogened
void get_callchain_buffers(void) { abort(); } // TODO --> autogened
void ksize(void) { abort(); } // TODO --> autogened
void sysctl_perf_event_max_stack(void) { abort(); } // TODO --> autogened
