#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// TODO: modify this so that custom capabilities can be specified
// and so that we can record what functions are asking about which
// capabilities.
bool capable(int cap) { return true; } // always true for test harness

// originally from /include/linux/slab.h
// stubbed out (decl as extern in "slab.h")
// TODO: some implemented may never be used
// some unimplemented may sometimes be used
void * kzalloc(size_t size) {
	void * res = malloc(size);
	memset(res, 0, size);
	return res;
}
// originally from include/linux/slab.h
void * kvcalloc(size_t n, size_t size) { return calloc(n, size); }

// originally from include/linux/slab.h
void kfree(void *ptr) { free(ptr); }

// originally from include/linux/slab.h
void kvfree(void *ptr) { free(ptr); }

// extern decl in  include/linux/vmalloc.h
void * __vmalloc(unsigned long size) { return malloc(size); }

// extern decl from include/linux/vmalloc.h
void * vzalloc(size_t size) {
	void * res = malloc(size);
	memset(res, 0, size);
	return res;
}

// extern decl from include/linux/vmalloc.h
void * vmalloc(unsigned long size) { return malloc(size); }


// extern decl from /include/linux/vmalloc.h
void vfree(void *ptr) { free(ptr); }

// originally a macro in include/linux/thread_info.h
bool tif_need_resched(void) {return false;}

// originally function from include/linux/sched/signal.h
int signal_pending(struct task_struct *p) { return false; }

// include/linux/sched/user.h
void free_uid(struct user_struct *) { return; }


// I only see this called twice in bpf_check --> just seems to be timing the
// verifier process.
// originally extern decl from include/linux/timekeeping.h
unsigned long ktime_get(void) {
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec;
}
// include/linux/timekeeping.h
int ktime_get_with_offset(void) { return 0; } // don't think time is actually relevant

// originally decl in include/linux/percpu.h
void * __alloc_percpu_gfp(size_t size, size_t align) { return malloc(size); }
// originally decl in include/linux/percpu.h
void free_percpu(void * ptr) { free(ptr); }

// originally a macro in include/linux/mutex.h
void __mutex_init(void) { return; }

// TODO: any need for real locks when verifying within harness?
void mutex_lock(void) { return; }
void mutex_unlock(void) { return; }

// originally decl in include/linux/security.h
int security_bpf_prog_alloc(struct bpf_prog_aux *aux) { return 0; }

// include/linux/cred.h
struct user_struct *get_current_user() { return NULL; }

// orig. in lib/vsprintf.c
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args) { return snprintf(buf, size, fmt, args); }

void _printk(void) { abort(); }

void kmem_cache_alloc_lru(void) { abort(); } // TODO --> autogened
void* kmem_cache_create_usercopy(void) { return NULL; } // TODO --> autogened
void kmem_cache_free(void) { abort(); } // TODO --> autogened
void* kmem_cache_create(void) {return NULL; }


// TODO: deal with this appropriately. Caused by includeing kernel/ksysfs.bc
void crash_get_memory_size(void) { abort(); } // TODO --> autogened
void crash_shrink_memory(void) { abort(); } // TODO --> autogened
void create_proc_profile(void) { abort(); } // TODO --> autogened
void file_caps_enabled(void) { abort(); } // TODO --> autogened
void kexec_crash_loaded(void) { abort(); } // TODO --> autogened
void kexec_image(void) { abort(); } // TODO --> autogened
void kobject_create_and_add(void) { abort(); } // TODO --> autogened
void kobject_put(void) { abort(); } // TODO --> autogened
void kstrtoint(void) { abort(); } // TODO --> autogened
void kstrtoull(void) { abort(); } // TODO --> autogened
void paddr_vmcoreinfo_note(void) { abort(); } // TODO --> autogened
void prof_on(void) { abort(); } // TODO --> autogened
void profile_init(void) { abort(); } // TODO --> autogened
void profile_setup(void) { abort(); } // TODO --> autogened
void register_module_notifier(void) { abort(); } // TODO --> autogened
void sysfs_create_bin_file(void) { abort(); } // TODO --> autogened
void sysfs_create_group(void) { abort(); } // TODO --> autogened
void sysfs_remove_bin_file(void) { abort(); } // TODO --> autogened
void sysfs_remove_group(void) { abort(); } // TODO --> autogened
void try_module_get(void) { abort(); } // TODO --> autogened
void uevent_seqnum(void) { abort(); } // TODO --> autogened



void ___pskb_trim(void) { abort(); }
void __arch_copy_from_user(void) { abort(); }
void __arch_copy_to_user(void) { abort(); }
void __bitmap_clear(void) { abort(); }
void __bitmap_set(void) { abort(); }
void __bitmap_weight(void) { abort(); }
void __bpf_prog_enter_sleepable(void) { abort(); }
void __bpf_prog_exit_sleepable(void) { abort(); }
void __cgroup_bpf_run_filter_skb(void) { abort(); }
void __cpu_map_flush(void) { abort(); }
void __cpu_possible_mask(void) { abort(); }
void __dev_flush(void) { abort(); }
void __do_once_done(void) { abort(); }
void __do_once_start(void) { abort(); }
void __fdget(void) { abort(); }
void __inet6_lookup_established(void) { abort(); }
void __inet_bind(void) { abort(); }
void __inet_lookup_established(void) { abort(); }
void __inet_lookup_listener(void) { abort(); }
void __ipv6_addr_type(void) { abort(); }
void __kmalloc_track_caller(void) { abort(); }
void __local_bh_enable_ip(void) { abort(); }
void __neigh_create(void) { abort(); }
void __per_cpu_offset(void) { abort(); }
void __pskb_pull_tail(void) { abort(); }
void __put_net(void) { abort(); }
void __put_page(void) { abort(); }
void __put_task_struct(void) { abort(); }
void __rcu_read_lock(void) { abort(); }
void __rcu_read_unlock(void) { abort(); }
void __sk_mem_reclaim(void) { abort(); }
void __skb_get_hash(void) { abort(); }
void __sock_gen_cookie(void) { abort(); }
void __sw_hweight64(void) { abort(); }
void __task_pid_nr_ns(void) { abort(); }
void __udp4_lib_lookup(void) { abort(); }
void __usecs_to_jiffies(void) { abort(); }
void __vmalloc_node_range(void) { abort(); }
void __warn_printk(void) { abort(); }
void __xdp_return(void) { abort(); }
void _ctype(void) { abort(); }
void _parse_integer(void) { abort(); }
void _parse_integer_fixup_radix(void) { abort(); }
void _raw_spin_lock(void) { abort(); }
void _raw_spin_lock_bh(void) { abort(); }
void _raw_spin_lock_irqsave(void) { abort(); }
void _raw_spin_unlock(void) { abort(); }
void _raw_spin_unlock_bh(void) { abort(); }
void _raw_spin_unlock_irqrestore(void) { abort(); }
void access_process_vm(void) { abort(); }
void alloc_pages(void) { abort(); }
void anon_inode_getfd(void) { abort(); }
void anon_inode_getfile(void) { abort(); }
void arm64_use_ng_mappings(void) { abort(); }
void arp_tbl(void) { abort(); }
void array_map_ops(void) { abort(); }
void array_of_maps_map_ops(void) { abort(); }
void audit_enabled(void) { abort(); }
void audit_log_end(void) { abort(); }
void audit_log_format(void) { abort(); }
void audit_log_start(void) { abort(); }
void bin2hex(void) { abort(); }
void bitmap_find_next_zero_area_off(void) { abort(); }
void bloom_filter_map_ops(void) { abort(); }
void bpf_cgroup_storage_assign(void) { abort(); }
void bpf_core_calc_relo_insn(void) { abort(); }
void bpf_core_patch_insn(void) { abort(); }
void bpf_dispatcher_change_prog(void) { abort(); }
void bpf_extension_prog_ops(void) { abort(); }
void bpf_extension_verifier_ops(void) { abort(); }
void bpf_fd_array_map_lookup_elem(void) { abort(); }
void bpf_fd_array_map_update_elem(void) { abort(); }
void bpf_fd_htab_map_lookup_elem(void) { abort(); }
void bpf_fd_htab_map_update_elem(void) { abort(); }
void bpf_fd_reuseport_array_lookup_elem(void) { abort(); }
void bpf_fd_reuseport_array_update_elem(void) { abort(); }
void bpf_for_each_map_elem_proto(void) { abort(); }
void bpf_iter_link_attach(void) { abort(); }
void bpf_iter_new_fd(void) { abort(); }
void bpf_iter_prog_supported(void) { abort(); }
void bpf_loop_proto(void) { abort(); }
void bpf_map_meta_equal(void) { abort(); }
void bpf_map_offload_delete_elem(void) { abort(); }
void bpf_map_offload_get_next_key(void) { abort(); }
void bpf_map_offload_info_fill(void) { abort(); }
void bpf_map_offload_lookup_elem(void) { abort(); }
void bpf_map_offload_map_alloc(void) { abort(); }
void bpf_map_offload_map_free(void) { abort(); }
void bpf_map_offload_update_elem(void) { abort(); }
void bpf_obj_get_user(void) { abort(); }
void bpf_obj_pin_user(void) { abort(); }
void bpf_offload_prog_map_match(void) { abort(); }
void bpf_offload_prog_ops(void) { abort(); }
void bpf_percpu_array_copy(void) { abort(); }
void bpf_percpu_array_update(void) { abort(); }
void bpf_percpu_cgroup_storage_copy(void) { abort(); }
void bpf_percpu_cgroup_storage_update(void) { abort(); }
void bpf_percpu_hash_copy(void) { abort(); }
void bpf_percpu_hash_update(void) { abort(); }
void bpf_prog_has_trampoline(void) { abort(); }
void bpf_prog_offload_compile(void) { abort(); }
void bpf_prog_offload_destroy(void) { abort(); }
void bpf_prog_offload_finalize(void) { abort(); }
void bpf_prog_offload_info_fill(void) { abort(); }
void bpf_prog_offload_init(void) { abort(); }
void bpf_prog_offload_remove_insns(void) { abort(); }
void bpf_prog_offload_replace_insn(void) { abort(); }
void bpf_prog_offload_verifier_prep(void) { abort(); }
void bpf_prog_offload_verify_insn(void) { abort(); }
void bpf_prog_test_run_flow_dissector(void) { abort(); }
void bpf_prog_test_run_sk_lookup(void) { abort(); }
void bpf_prog_test_run_skb(void) { abort(); }
void bpf_prog_test_run_syscall(void) { abort(); }
void bpf_prog_test_run_xdp(void) { abort(); }
void bpf_ringbuf_discard_proto(void) { abort(); }
void bpf_ringbuf_output_proto(void) { abort(); }
void bpf_ringbuf_query_proto(void) { abort(); }
void bpf_ringbuf_reserve_proto(void) { abort(); }
void bpf_ringbuf_submit_proto(void) { abort(); }
void bpf_struct_ops_find(void) { abort(); }
void bpf_struct_ops_init(void) { abort(); }
void bpf_struct_ops_map_ops(void) { abort(); }
void bpf_struct_ops_map_sys_lookup_elem(void) { abort(); }
void bpf_struct_ops_prog_ops(void) { abort(); }
void bpf_struct_ops_verifier_ops(void) { abort(); }
void bpf_trampoline_get(void) { abort(); }
void bpf_trampoline_link_prog(void) { abort(); }
void bpf_trampoline_put(void) { abort(); }
void bpf_trampoline_unlink_prog(void) { abort(); }
void bpf_xdp_link_attach(void) { abort(); }
void bstr_printf(void) { abort(); }
void call_rcu(void) { abort(); }
void call_rcu_tasks_trace(void) { abort(); }

void cg_dev_prog_ops(void) { abort(); }
void cg_dev_verifier_ops(void) { abort(); }
void cg_sockopt_prog_ops(void) { abort(); }
void cg_sockopt_verifier_ops(void) { abort(); }
void cg_sysctl_prog_ops(void) { abort(); }
void cg_sysctl_verifier_ops(void) { abort(); }
void cgroup_array_map_ops(void) { abort(); }
void cgroup_bpf_enabled_key(void) { abort(); }
void cgroup_bpf_link_attach(void) { abort(); }
void cgroup_bpf_prog_attach(void) { abort(); }
void cgroup_bpf_prog_detach(void) { abort(); }
void cgroup_bpf_prog_query(void) { abort(); }
void cgroup_storage_map_ops(void) { abort(); }
void check_copy_size(void) { abort(); }
void check_zeroed_user(void) { abort(); }
void close_fd(void) { abort(); }
void copy_from_kernel_nofault(void) { abort(); }
void cpu_hwcap_keys(void) { abort(); }
void cpu_map_enqueue(void) { abort(); }
void cpu_map_generic_redirect(void) { abort(); }
void cpu_map_ops(void) { abort(); }
void cpu_number(void) { abort(); }
void cpumask_next(void) { abort(); }
void csum_partial(void) { abort(); }
void current_cred(void) { abort(); }
void dev_forward_skb_nomtu(void) { abort(); }
void dev_get_by_index_rcu(void) { abort(); }
void dev_get_by_name(void) { abort(); }
void dev_map_enqueue(void) { abort(); }
void dev_map_enqueue_multi(void) { abort(); }
void dev_map_generic_redirect(void) { abort(); }
void dev_map_hash_ops(void) { abort(); }
void dev_map_ops(void) { abort(); }
void dev_map_redirect_multi(void) { abort(); }
void dev_queue_xmit(void) { abort(); }
void dev_xdp_enqueue(void) { abort(); }
void dst_release(void) { abort(); }
void fd_install(void) { abort(); }
void fget_task(void) { abort(); }
void fib_select_path(void) { abort(); }
void fib_table_lookup(void) { abort(); }
void find_vm_area(void) { abort(); }
void find_vpid(void) { abort(); }
void from_kgid(void) { abort(); }
void from_kuid(void) { abort(); }
void from_kuid_munged(void) { abort(); }
void generic_xdp_tx(void) { abort(); }
void get_callchain_buffers(void) { abort(); }
void get_mem_cgroup_from_mm(void) { abort(); }
void get_net_ns_by_id(void) { abort(); }
void get_pid_task(void) { abort(); }
void get_random_u32(void) { abort(); }
void get_unused_fd_flags(void) { abort(); }
void gic_nonsecure_priorities(void) { abort(); }
void hrtimer_cancel(void) { abort(); }
void hrtimer_init(void) { abort(); }
void hrtimer_start_range_ns(void) { abort(); }
void htab_lru_map_ops(void) { abort(); }
void htab_lru_percpu_map_ops(void) { abort(); }
void htab_map_ops(void) { abort(); }
void htab_of_maps_map_ops(void) { abort(); }
void htab_percpu_map_ops(void) { abort(); }
void idr_alloc_cyclic(void) { abort(); }
void idr_find(void) { abort(); }
void idr_get_next(void) { abort(); }
void idr_preload(void) { abort(); }
void idr_remove(void) { abort(); }
void inet6_lookup_listener(void) { abort(); }
void inet_proto_csum_replace4(void) { abort(); }
void inet_proto_csum_replace_by_diff(void) { abort(); }
void init_net(void) { abort(); }
void init_user_ns(void) { abort(); }
void int_active_memcg(void) { abort(); }
void ip_mtu_from_fib_result(void) { abort(); }
void ip_route_output_flow(void) { abort(); }
void ipv6_stub(void) { abort(); }
void is_skb_forwardable(void) { abort(); }
void jiffies(void) { abort(); }
void kallsyms_lookup_name(void) { abort(); }
void kallsyms_show_value(void) { abort(); }
void kcalloc(void) { abort(); }
void kfree_skb_reason(void) { abort(); }
void kmalloc(void) { abort(); }
void kmalloc_array(void) { abort(); }
void kmalloc_node(void) { abort(); }
void kmemdup(void) { abort(); }
void kmemdup_nul(void) { abort(); }
void krealloc(void) { abort(); }
void krealloc_array(void) { abort(); }
void ksize(void) { abort(); }
void ktime_get_boot_fast_ns(void) { abort(); }
void ktime_get_coarse_ts64(void) { abort(); }
void ktime_get_mono_fast_ns(void) { abort(); }
void kvfree_call_rcu(void) { abort(); }
void kvmalloc(void) { abort(); }
void lock_sock_nested(void) { abort(); }
void make_kuid(void) { abort(); }
void metadata_dst_alloc_percpu(void) { abort(); }
void metadata_dst_free_percpu(void) { abort(); }
void migrate_disable(void) { abort(); }
void migrate_enable(void) { abort(); }
void module_alloc(void) { abort(); }
void module_memfree(void) { abort(); }
void module_put(void) { abort(); }
void msg_zerocopy_callback(void) { abort(); }
void net_ratelimit(void) { abort(); }
void netdev_core_stats_alloc(void) { abort(); }
void netdev_master_upper_dev_get_rcu(void) { abort(); }
void netif_rx(void) { abort(); }
void netns_bpf_link_create(void) { abort(); }
void netns_bpf_prog_attach(void) { abort(); }
void netns_bpf_prog_detach(void) { abort(); }
void netns_bpf_prog_query(void) { abort(); }
void nla_find(void) { abort(); }
void node_states(void) { abort(); }
void nr_cpu_ids(void) { abort(); }
void nr_node_ids(void) { abort(); }
void ns_match(void) { abort(); }
void numa_node(void) { abort(); }
void overflowuid(void) { abort(); }
void percpu_array_map_ops(void) { abort(); }
void perf_event_array_map_ops(void) { abort(); }
void perf_event_bpf_event(void) { abort(); }
void perf_event_free_bpf_prog(void) { abort(); }
void perf_event_get(void) { abort(); }
void perf_event_set_bpf_prog(void) { abort(); }
void perf_get_event(void) { abort(); }
void prandom_seed_full_state(void) { abort(); }
void prandom_u32_state(void) { abort(); }
void preempt_schedule(void) { abort(); }
void preempt_schedule_notrace(void) { abort(); }
void prog_array_map_ops(void) { abort(); }
void pskb_expand_head(void) { abort(); }
void put_callchain_buffers(void) { abort(); }
void put_unused_fd(void) { abort(); }
void queue_map_ops(void) { abort(); }
void queue_work_on(void) { abort(); }
void queued_spin_lock_slowpath(void) { abort(); }
void rb_erase(void) { abort(); }
void rb_insert_color(void) { abort(); }
void refcount_warn_saturate(void) { abort(); }
void release_sock(void) { abort(); }
void reuseport_array_ops(void) { abort(); }
void reuseport_attach_prog(void) { abort(); }
void ringbuf_map_ops(void) { abort(); }
void sched_clock(void) { abort(); }
void search_extable(void) { abort(); }
void security_bpf(void) { abort(); }
void security_bpf_map(void) { abort(); }
void security_bpf_map_alloc(void) { abort(); }
void security_bpf_map_free(void) { abort(); }
void security_bpf_prog(void) { abort(); }
void security_bpf_prog_free(void) { abort(); }
void security_locked_down(void) { abort(); }
void seq_printf(void) { abort(); }
void seq_vprintf(void) { abort(); }
void set_memory_ro(void) { abort(); }
void set_memory_x(void) { abort(); }
void sk_free(void) { abort(); }
void sk_storage_map_ops(void) { abort(); }
void skb_clone(void) { abort(); }
void skb_copy_ubufs(void) { abort(); }
void skb_ensure_writable(void) { abort(); }
void skb_expand_head(void) { abort(); }
void skb_get_poff(void) { abort(); }
void skb_gso_validate_network_len(void) { abort(); }
void skb_pull(void) { abort(); }
void skb_push(void) { abort(); }
void skb_scrub_packet(void) { abort(); }
void skb_vlan_pop(void) { abort(); }
void skb_vlan_push(void) { abort(); }
void sock_bindtoindex(void) { abort(); }
void sock_from_file(void) { abort(); }
void sock_gen_put(void) { abort(); }
void sock_hash_ops(void) { abort(); }
void sock_map_bpf_prog_query(void) { abort(); }
void sock_map_get_from_fd(void) { abort(); }
void sock_map_ops(void) { abort(); }
void sock_map_prog_detach(void) { abort(); }
void sock_map_update_elem_sys(void) { abort(); }
void sock_pfree(void) { abort(); }
void softnet_data(void) { abort(); }
void stack_map_ops(void) { abort(); }
void stack_trace_map_ops(void) { abort(); }
void static_key_count(void) { abort(); }
void static_key_slow_dec(void) { abort(); }
void static_key_slow_inc(void) { abort(); }
void strncpy_from_kernel_nofault(void) { abort(); }
void strncpy_from_user(void) { abort(); }
void strncpy_from_user_nofault(void) { abort(); }
void synchronize_rcu(void) { abort(); }
void sysctl_optmem_max(void) { abort(); }
void sysctl_perf_event_max_stack(void) { abort(); }
void sysctl_rmem_max(void) { abort(); }
void sysctl_wmem_max(void) { abort(); }
void system_wq(void) { abort(); }
void task_active_pid_ns(void) { abort(); }
void task_storage_map_ops(void) { abort(); }
void tcp_getsockopt(void) { abort(); }
void tcp_hashinfo(void) { abort(); }
void tcp_prot(void) { abort(); }
void tcp_set_congestion_control(void) { abort(); }
void tcp_set_window_clamp(void) { abort(); }
void tcp_setsockopt(void) { abort(); }
void tcp_sock_set_keepidle_locked(void) { abort(); }
void test_thread_flag(void) { abort(); }
void trie_map_ops(void) { abort(); }
void udp_table(void) { abort(); }
void vabits_actual(void) { abort(); }
void vmemdup_user(void) { abort(); }
void xdp_convert_zc_to_xdp_frame(void) { abort(); }
void xdp_warn(void) { abort(); }


// caused by fs/dcache.o
void ___ratelimit(void) { abort(); } // TODO --> autogened
void __detach_mounts(void) { abort(); } // TODO --> autogened
void __fsnotify_inode_delete(void) { abort(); } // TODO --> autogened
void __kmalloc(void) { abort(); } // TODO --> autogened
void __lookup_mnt(void) { abort(); } // TODO --> autogened
void __mark_inode_dirty(void) { abort(); } // TODO --> autogened
void __register_sysctl_init(void) { abort(); } // TODO --> autogened
void __wake_up(void) { abort(); } // TODO --> autogened
void _raw_spin_trylock(void) { abort(); } // TODO --> autogened
void add_wait_queue(void) { abort(); } // TODO --> autogened
void * alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit) { return malloc(10*bucketsize); } // TODO --> autogened
void bdev_cache_init(void) { return; } // TODO --> autogened
void chrdev_init(void) { return; } // TODO --> autogened
void default_wake_function(void) { abort(); } // TODO --> autogened
void down_read_trylock(void) { abort(); } // TODO --> autogened
void fsnotify(void) { abort(); } // TODO --> autogened
void full_name_hash(void) { abort(); } // TODO --> autogened
void hashdist(void) { abort(); } // TODO --> autogened
void hashlen_string(void) { abort(); } // TODO --> autogened
void list_lru_add(void) { abort(); } // TODO --> autogened
void list_lru_count_node(void) { abort(); } // TODO --> autogened
void list_lru_del(void) { abort(); } // TODO --> autogened
void list_lru_isolate(void) { abort(); } // TODO --> autogened
void list_lru_isolate_move(void) { abort(); } // TODO --> autogened
void list_lru_walk_node(void) { abort(); } // TODO --> autogened
void list_lru_walk_one(void) { abort(); } // TODO --> autogened
void lockref_get(void) { abort(); } // TODO --> autogened
void lockref_get_not_dead(void) { abort(); } // TODO --> autogened
void lockref_get_not_zero(void) { abort(); } // TODO --> autogened
void lockref_mark_dead(void) { abort(); } // TODO --> autogened
void lockref_put_or_lock(void) { abort(); } // TODO --> autogened
void lockref_put_return(void) { abort(); } // TODO --> autogened
void mnt_init(void) { return; } // TODO --> autogened
void mount_lock(void) { abort(); } // TODO --> autogened
void mutex_trylock(void) { abort(); } // TODO --> autogened
void proc_doulongvec_minmax(void) { abort(); } // TODO --> autogened
void schedule(void) { abort(); } // TODO --> autogened
void security_d_instantiate(void) { abort(); } // TODO --> autogened
void simple_strtoul(void) { abort(); } // TODO --> autogened
void up_read(void) { abort(); } // TODO --> autogened
void wake_up_bit(void) { abort(); } // TODO --> autogened


// from fs/inode.o
void __init_rwsem(void) { abort(); } // TODO --> autogened
void __mnt_drop_write(void) { abort(); } // TODO --> autogened
void __mnt_drop_write_file(void) { abort(); } // TODO --> autogened
void __mnt_want_write(void) { abort(); } // TODO --> autogened
void __mnt_want_write_file(void) { abort(); } // TODO --> autogened
void __percpu_down_read(void) { abort(); } // TODO --> autogened
void _atomic_dec_and_lock(void) { abort(); } // TODO --> autogened
void _raw_spin_lock_irq(void) { abort(); } // TODO --> autogened
void _raw_spin_unlock_irq(void) { abort(); } // TODO --> autogened
void bit_wait(void) { abort(); } // TODO --> autogened
void bit_waitqueue(void) { abort(); } // TODO --> autogened
void capable_wrt_inode_uidgid(void) { abort(); } // TODO --> autogened
void cd_forget(void) { abort(); } // TODO --> autogened
void def_blk_fops(void) { abort(); } // TODO --> autogened
void def_chr_fops(void) { abort(); } // TODO --> autogened
void down_write(void) { abort(); } // TODO --> autogened
void finish_wait(void) { abort(); } // TODO --> autogened
void in_group_p(void) { abort(); } // TODO --> autogened
void inode_has_buffers(void) { abort(); } // TODO --> autogened
void inode_io_list_del(void) { abort(); } // TODO --> autogened
void inode_wait_for_writeback(void) { abort(); } // TODO --> autogened
void invalidate_mapping_pages(void) { abort(); } // TODO --> autogened
void ktime_get_coarse_real_ts64(void) { abort(); } // TODO --> autogened
void locks_free_lock_context(void) { abort(); } // TODO --> autogened
void make_kgid(void) { abort(); } // TODO --> autogened
void notify_change(void) { abort(); } // TODO --> autogened
void ns_capable(void) { abort(); } // TODO --> autogened
void out_of_line_wait_on_bit(void) { abort(); } // TODO --> autogened
void pipefifo_fops(void) { abort(); } // TODO --> autogened
void prepare_to_wait(void) { abort(); } // TODO --> autogened
void rcuwait_wake_up(void) { abort(); } // TODO --> autogened
void remove_inode_buffers(void) { abort(); } // TODO --> autogened
void security_inode_alloc(void) { abort(); } // TODO --> autogened
void security_inode_free(void) { abort(); } // TODO --> autogened
void security_inode_need_killpriv(void) { abort(); } // TODO --> autogened
void truncate_inode_pages_final(void) { abort(); } // TODO --> autogened
void up_write(void) { abort(); } // TODO --> autogened
void vm_event_states(void) { abort(); } // TODO --> autogened
void wake_bit_function(void) { abort(); } // TODO --> autogened
void write_inode_now(void) { abort(); } // TODO --> autogened

// from file_table.o
void __fsnotify_parent(void) { abort(); } // TODO --> autogened
void __percpu_counter_init(void)  { return; } // TODO --> autogened
void __percpu_counter_sum(void) { abort(); } // TODO --> autogened
void __put_cred(void) { abort(); } // TODO --> autogened
void _totalram_pages(void) { abort(); } // TODO --> autogened
void cdev_put(void) { abort(); } // TODO --> autogened
void delayed_work_timer_fn(void) { abort(); } // TODO --> autogened
void dissolve_on_fput(void) { abort(); } // TODO --> autogened
void errseq_sample(void) { abort(); } // TODO --> autogened
void eventpoll_release_file(void) { abort(); } // TODO --> autogened
void kmem_cache_zalloc(void) { abort(); } // TODO --> autogened
void llist_add_batch(void) { abort(); } // TODO --> autogened
void locks_remove_file(void) { abort(); } // TODO --> autogened
void mntget(void) { abort(); } // TODO --> autogened
void mntput(void) { abort(); } // TODO --> autogened
void path_get(void) { abort(); } // TODO --> autogened
void path_put(void) { abort(); } // TODO --> autogened
void percpu_counter_add_batch(void) { abort(); } // TODO --> autogened
void percpu_counter_batch(void) { abort(); } // TODO --> autogened
void proc_dointvec_minmax(void) { abort(); } // TODO --> autogened
void put_pid(void) { abort(); } // TODO --> autogened
void queue_delayed_work_on(void) { abort(); } // TODO --> autogened
void security_file_alloc(void) { abort(); } // TODO --> autogened
void security_file_free(void) { abort(); } // TODO --> autogened
void simple_dname(void) { abort(); } // TODO --> autogened
void sysctl_long_vals(void) { abort(); } // TODO --> autogened
void sysctl_nr_open(void) { abort(); } // TODO --> autogened
void sysctl_nr_open_max(void) { abort(); } // TODO --> autogened
void sysctl_nr_open_min(void) { abort(); } // TODO --> autogened
void task_work_add(void) { abort(); } // TODO --> autogened
void vm_zone_stat(void) { abort(); } // TODO --> autogened
