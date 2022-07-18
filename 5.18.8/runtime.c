#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <setjmp.h>


// TODO: split testing functions out to a separate file.
extern int bpf_prog_load(union bpf_attr *, bpfptr_t);
jmp_buf env_buffer;

void test(union bpf_attr *a, bpfptr_t *b, char * descr ) {
	int res = setjmp(env_buffer);
	if (res != 0) {
		switch (res) {
			case 1:
				printf("Test \"%s\": REJECTED\n", descr);
				break;
			case 2:
				printf("Test \"%s\": ACCEPTED\n", descr);
				break;
			default:
				printf("Unrecognized return value %d.\n", res);
		}
	} else {
		bpf_prog_load(a, *b);
	}
}

// add to core.bc compile command: -Dbpf_prog_select_runtime=bpf_prog_select_runtime_orig -Dbpf_prog_kallsyms_del_all=bpf_prog_kallsyms_del_all_orig
void bpf_prog_kallsyms_del_all(struct bpf_prog *fp) {
	__bpf_prog_free(fp);
	longjmp(env_buffer, 1);
}
void bpf_prog_select_runtime(struct bpf_prog *fp, int *err) {
	__bpf_prog_free(fp);
	longjmp(env_buffer, 2);
}

// stubbed out (decl as extern in "slab.h")
// TODO: some implemented may never be used
// some unimplemented may sometimes be used
void * kzalloc(size_t size) {
	void * res = malloc(size);
	memset(res, 0, size);
	return res;
}
void * kvcalloc(size_t n, size_t size) { return calloc(n, size); }
void * __vmalloc(unsigned long size) { return malloc(size); }
void * vzalloc(size_t size) {
	void * res = malloc(size);
	memset(res, 0, size);
	return res;
}
void * vmalloc(unsigned long size) { return malloc(size); }

void kfree(void *ptr) { free(ptr); }
void vfree(void *ptr) { free(ptr); }
void kvfree(void *ptr) { free(ptr); }

void __kmalloc_track_caller(void) { abort(); } // TODO --> autogened
void kcalloc(void) { abort(); } // TODO --> autogened
void kmalloc(void) { abort(); } // TODO --> autogened
void kmalloc_array(void) { abort(); } // TODO --> autogened
void kmalloc_node(void) { abort(); } // TODO --> autogened
void krealloc(void) { abort(); } // TODO --> autogened
void krealloc_array(void) { abort(); } // TODO --> autogened
void ksize(void) { abort(); } // TODO --> autogened
void kvmalloc(void) { abort(); } // TODO --> autogened

// from signal.h
int signal_pending(struct task_struct *p) { return false; }

void clear_siginfo(void) { abort(); } // TODO --> autogened
void fatal_signal_pending(void) { abort(); } // TODO --> autogened
void force_sig_info(void) { abort(); } // TODO --> autogened
void put_task_struct(void) { abort(); } // TODO --> autogened
void same_thread_group(void) { abort(); } // TODO --> autogened
void send_sig(void) { abort(); } // TODO --> autogened
void sigaddset(void) { abort(); } // TODO --> autogened
void task_set_jobctl_pending(void) { abort(); } // TODO --> autogened
void task_tgid(void) { abort(); } // TODO --> autogened

// for current.h
struct task_struct *get_current(void) { return NULL; }

// // I only see this called twice in bpf_check --> just seems to be timing the
// // verifier process.
unsigned long ktime_get(void) {
  struct timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec;
}

// TODO: modify this so that custom capabilities can be specified
// and so that we can record what functions are asking about which
// capabilities.
bool capable(int cap) { return true; } // always true for test harness

void * __alloc_percpu_gfp(size_t size, size_t align) { return malloc(size); } // TODO --> autogened
void free_percpu(void * ptr) { free(ptr); } // TODO --> autogened


void __mutex_init(void) { return; } // TODO --> autogened
int security_bpf_prog_alloc(struct bpf_prog_aux *aux) { return 0; } // TODO --> autogened

struct user_struct *get_current_user() { return NULL; }
void current_uid_gid(int *uid, int *gid) { abort(); }
void current_cred(void) { abort(); }

void free_uid(struct user_struct *) { return; } // TODO --> autogened
void security_bpf_prog_free(struct bpf_prog_aux *) { return; } // TODO --> autogened

int ktime_get_with_offset(void) { return 0; } // don't think time is actually relevant

// don't think this matters --> maybe makes more sense to just
// stub out workqueue.h???
// this may not even be needed anymore
bool queue_work_on(void) { return true; } // TODO --> autogened

void ___pskb_trim(void) { abort(); } // TODO --> autogened
void __arch_copy_from_user(void) { abort(); } // TODO --> autogened
void __arch_copy_to_user(void) { abort(); } // TODO --> autogened
void __bitmap_clear(void) { abort(); } // TODO --> autogened
void __bitmap_set(void) { abort(); } // TODO --> autogened
void __bitmap_weight(void) { abort(); } // TODO --> autogened
void __bpf_prog_enter_sleepable(void) { abort(); } // TODO --> autogened
void __bpf_prog_exit_sleepable(void) { abort(); } // TODO --> autogened
void __cgroup_bpf_run_filter_skb(void) { abort(); } // TODO --> autogened
void __cpu_map_flush(void) { abort(); } // TODO --> autogened
void __cpu_possible_mask(void) { abort(); } // TODO --> autogened
void __dev_flush(void) { abort(); } // TODO --> autogened
void __do_once_done(void) { abort(); } // TODO --> autogened
void __do_once_start(void) { abort(); } // TODO --> autogened
void __fdget(void) { abort(); } // TODO --> autogened
void __inet6_lookup_established(void) { abort(); } // TODO --> autogened
void __inet_bind(void) { abort(); } // TODO --> autogened
void __inet_lookup_established(void) { abort(); } // TODO --> autogened
void __inet_lookup_listener(void) { abort(); } // TODO --> autogened
void __ipv6_addr_type(void) { abort(); } // TODO --> autogened
void __local_bh_enable_ip(void) { abort(); } // TODO --> autogened
void __neigh_create(void) { abort(); } // TODO --> autogened
void __per_cpu_offset(void) { abort(); } // TODO --> autogened
void __pskb_pull_tail(void) { abort(); } // TODO --> autogened
void __put_net(void) { abort(); } // TODO --> autogened
void __put_page(void) { abort(); } // TODO --> autogened
void __rcu_read_lock(void) { abort(); } // TODO --> autogened
void __rcu_read_unlock(void) { abort(); } // TODO --> autogened
void __sk_mem_reclaim(void) { abort(); } // TODO --> autogened
void __skb_get_hash(void) { abort(); } // TODO --> autogened
void __sock_gen_cookie(void) { abort(); } // TODO --> autogened
void __sw_hweight64(void) { abort(); } // TODO --> autogened
void __udp4_lib_lookup(void) { abort(); } // TODO --> autogened
void __usecs_to_jiffies(void) { abort(); } // TODO --> autogened
void __vmalloc_node_range(void) { abort(); } // TODO --> autogened
void __warn_printk(void) { abort(); } // TODO --> autogened
void __xdp_return(void) { abort(); } // TODO --> autogened
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
void alloc_pages(void) { abort(); } // TODO --> autogened
void anon_inode_getfd(void) { abort(); } // TODO --> autogened
void anon_inode_getfile(void) { abort(); } // TODO --> autogened
void arm64_use_ng_mappings(void) { abort(); } // TODO --> autogened
void arp_tbl(void) { abort(); } // TODO --> autogened
void array_map_ops(void) { abort(); } // TODO --> autogened
void array_of_maps_map_ops(void) { abort(); } // TODO --> autogened
void audit_enabled(void) { abort(); } // TODO --> autogened
void audit_log_end(void) { abort(); } // TODO --> autogened
void audit_log_format(void) { abort(); } // TODO --> autogened
void audit_log_start(void) { abort(); } // TODO --> autogened
void bin2hex(void) { abort(); } // TODO --> autogened
void bitmap_find_next_zero_area_off(void) { abort(); } // TODO --> autogened
void bloom_filter_map_ops(void) { abort(); } // TODO --> autogened
void bpf_cgroup_storage_assign(void) { abort(); } // TODO --> autogened
void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
void bpf_dispatcher_change_prog(void) { abort(); } // TODO --> autogened
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
void bpf_iter_prog_supported(void) { abort(); } // TODO --> autogened
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
void bpf_offload_prog_map_match(void) { abort(); } // TODO --> autogened
void bpf_offload_prog_ops(void) { abort(); } // TODO --> autogened
void bpf_percpu_array_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_array_update(void) { abort(); } // TODO --> autogened
void bpf_percpu_cgroup_storage_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_cgroup_storage_update(void) { abort(); } // TODO --> autogened
void bpf_percpu_hash_copy(void) { abort(); } // TODO --> autogened
void bpf_percpu_hash_update(void) { abort(); } // TODO --> autogened
void bpf_prog_has_trampoline(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_compile(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_destroy(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_finalize(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_info_fill(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_init(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_remove_insns(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_replace_insn(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verifier_prep(void) { abort(); } // TODO --> autogened
void bpf_prog_offload_verify_insn(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_flow_dissector(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_sk_lookup(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_skb(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_syscall(void) { abort(); } // TODO --> autogened
void bpf_prog_test_run_xdp(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_discard_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_output_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_query_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_reserve_proto(void) { abort(); } // TODO --> autogened
void bpf_ringbuf_submit_proto(void) { abort(); } // TODO --> autogened
void bpf_struct_ops_find(void) { abort(); } // TODO --> autogened
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
void call_rcu(void) { abort(); } // TODO --> autogened
void call_rcu_tasks_trace(void) { abort(); } // TODO --> autogened
void cg_dev_prog_ops(void) { abort(); } // TODO --> autogened
void cg_dev_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sockopt_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sockopt_verifier_ops(void) { abort(); } // TODO --> autogened
void cg_sysctl_prog_ops(void) { abort(); } // TODO --> autogened
void cg_sysctl_verifier_ops(void) { abort(); } // TODO --> autogened
void cgroup_array_map_ops(void) { abort(); } // TODO --> autogened
void cgroup_bpf_enabled_key(void) { abort(); } // TODO --> autogened
void cgroup_bpf_link_attach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_attach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_detach(void) { abort(); } // TODO --> autogened
void cgroup_bpf_prog_query(void) { abort(); } // TODO --> autogened
void cgroup_storage_map_ops(void) { abort(); } // TODO --> autogened
void check_zeroed_user(void) { abort(); } // TODO --> autogened
void close_fd(void) { abort(); } // TODO --> autogened
void copy_from_kernel_nofault(void) { abort(); } // TODO --> autogened
void cpu_hwcap_keys(void) { abort(); } // TODO --> autogened
void cpu_map_enqueue(void) { abort(); } // TODO --> autogened
void cpu_map_generic_redirect(void) { abort(); } // TODO --> autogened
void cpu_map_ops(void) { abort(); } // TODO --> autogened
void cpu_number(void) { abort(); } // TODO --> autogened
void cpumask_next(void) { abort(); } // TODO --> autogened
void csum_partial(void) { abort(); } // TODO --> autogened
void dev_forward_skb_nomtu(void) { abort(); } // TODO --> autogened
void dev_get_by_index_rcu(void) { abort(); } // TODO --> autogened
void dev_get_by_name(void) { abort(); } // TODO --> autogened
void dev_map_enqueue(void) { abort(); } // TODO --> autogened
void dev_map_enqueue_multi(void) { abort(); } // TODO --> autogened
void dev_map_generic_redirect(void) { abort(); } // TODO --> autogened
void dev_map_hash_ops(void) { abort(); } // TODO --> autogened
void dev_map_ops(void) { abort(); } // TODO --> autogened
void dev_map_redirect_multi(void) { abort(); } // TODO --> autogened
void dev_queue_xmit(void) { abort(); } // TODO --> autogened
void dev_xdp_enqueue(void) { abort(); } // TODO --> autogened
void dst_release(void) { abort(); } // TODO --> autogened
void fd_install(void) { abort(); } // TODO --> autogened
void fget_task(void) { abort(); } // TODO --> autogened
void fib_select_path(void) { abort(); } // TODO --> autogened
void fib_table_lookup(void) { abort(); } // TODO --> autogened
void find_vm_area(void) { abort(); } // TODO --> autogened
void find_vpid(void) { abort(); } // TODO --> autogened
void fput(void) { abort(); } // TODO --> autogened
void from_kuid_munged(void) { abort(); } // TODO --> autogened
void generic_xdp_tx(void) { abort(); } // TODO --> autogened
void get_callchain_buffers(void) { abort(); } // TODO --> autogened
void get_mem_cgroup_from_mm(void) { abort(); } // TODO --> autogened
void get_net_ns_by_id(void) { abort(); } // TODO --> autogened
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
void inet6_lookup_listener(void) { abort(); } // TODO --> autogened
void inet_proto_csum_replace4(void) { abort(); } // TODO --> autogened
void inet_proto_csum_replace_by_diff(void) { abort(); } // TODO --> autogened
void init_net(void) { abort(); } // TODO --> autogened
void int_active_memcg(void) { abort(); } // TODO --> autogened
void ip_mtu_from_fib_result(void) { abort(); } // TODO --> autogened
void ip_route_output_flow(void) { abort(); } // TODO --> autogened
void ipv6_stub(void) { abort(); } // TODO --> autogened
void is_skb_forwardable(void) { abort(); } // TODO --> autogened
void jiffies(void) { abort(); } // TODO --> autogened
void kallsyms_lookup_name(void) { abort(); } // TODO --> autogened
void kallsyms_show_value(void) { abort(); } // TODO --> autogened
void kfree_skb_reason(void) { abort(); } // TODO --> autogened
void kmemdup(void) { abort(); } // TODO --> autogened
void kmemdup_nul(void) { abort(); } // TODO --> autogened
void ktime_get_boot_fast_ns(void) { abort(); } // TODO --> autogened
void ktime_get_coarse_ts64(void) { abort(); } // TODO --> autogened
void ktime_get_mono_fast_ns(void) { abort(); } // TODO --> autogened
void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
void lock_sock_nested(void) { abort(); } // TODO --> autogened
void make_kuid(void) { abort(); } // TODO --> autogened
void metadata_dst_alloc_percpu(void) { abort(); } // TODO --> autogened
void metadata_dst_free_percpu(void) { abort(); } // TODO --> autogened
void migrate_disable(void) { abort(); } // TODO --> autogened
void migrate_enable(void) { abort(); } // TODO --> autogened
void module_alloc(void) { abort(); } // TODO --> autogened
void module_memfree(void) { abort(); } // TODO --> autogened
void module_put(void) { abort(); } // TODO --> autogened
void msg_zerocopy_callback(void) { abort(); } // TODO --> autogened
void mutex_lock(void) { abort(); } // TODO --> autogened
void mutex_unlock(void) { abort(); } // TODO --> autogened
void net_ratelimit(void) { abort(); } // TODO --> autogened
void netdev_core_stats_alloc(void) { abort(); } // TODO --> autogened
void netdev_master_upper_dev_get_rcu(void) { abort(); } // TODO --> autogened
void netif_rx(void) { abort(); } // TODO --> autogened
void netns_bpf_link_create(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_attach(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_detach(void) { abort(); } // TODO --> autogened
void netns_bpf_prog_query(void) { abort(); } // TODO --> autogened
void nla_find(void) { abort(); } // TODO --> autogened
void node_states(void) { abort(); } // TODO --> autogened
void nr_cpu_ids(void) { abort(); } // TODO --> autogened
void nr_node_ids(void) { abort(); } // TODO --> autogened
void numa_node(void) { abort(); } // TODO --> autogened
void overflowuid(void) { abort(); } // TODO --> autogened
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
void pskb_expand_head(void) { abort(); } // TODO --> autogened
void put_callchain_buffers(void) { abort(); } // TODO --> autogened
void put_unused_fd(void) { abort(); } // TODO --> autogened
void queue_map_ops(void) { abort(); } // TODO --> autogened
void queued_spin_lock_slowpath(void) { abort(); } // TODO --> autogened
void rb_erase(void) { abort(); } // TODO --> autogened
void rb_insert_color(void) { abort(); } // TODO --> autogened
void refcount_warn_saturate(void) { abort(); } // TODO --> autogened
void release_sock(void) { abort(); } // TODO --> autogened
void reuseport_array_ops(void) { abort(); } // TODO --> autogened
void reuseport_attach_prog(void) { abort(); } // TODO --> autogened
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
void sk_free(void) { abort(); } // TODO --> autogened
void sk_storage_map_ops(void) { abort(); } // TODO --> autogened
void skb_clone(void) { abort(); } // TODO --> autogened
void skb_copy_ubufs(void) { abort(); } // TODO --> autogened
void skb_ensure_writable(void) { abort(); } // TODO --> autogened
void skb_expand_head(void) { abort(); } // TODO --> autogened
void skb_get_poff(void) { abort(); } // TODO --> autogened
void skb_gso_validate_network_len(void) { abort(); } // TODO --> autogened
void skb_pull(void) { abort(); } // TODO --> autogened
void skb_push(void) { abort(); } // TODO --> autogened
void skb_scrub_packet(void) { abort(); } // TODO --> autogened
void skb_vlan_pop(void) { abort(); } // TODO --> autogened
void skb_vlan_push(void) { abort(); } // TODO --> autogened
void sock_bindtoindex(void) { abort(); } // TODO --> autogened
void sock_from_file(void) { abort(); } // TODO --> autogened
void sock_gen_put(void) { abort(); } // TODO --> autogened
void sock_hash_ops(void) { abort(); } // TODO --> autogened
void sock_map_bpf_prog_query(void) { abort(); } // TODO --> autogened
void sock_map_get_from_fd(void) { abort(); } // TODO --> autogened
void sock_map_ops(void) { abort(); } // TODO --> autogened
void sock_map_prog_detach(void) { abort(); } // TODO --> autogened
void sock_map_update_elem_sys(void) { abort(); } // TODO --> autogened
void sock_pfree(void) { abort(); } // TODO --> autogened
void softnet_data(void) { abort(); } // TODO --> autogened
void stack_map_ops(void) { abort(); } // TODO --> autogened
void stack_trace_map_ops(void) { abort(); } // TODO --> autogened
void static_key_count(void) { abort(); } // TODO --> autogened
void static_key_slow_dec(void) { abort(); } // TODO --> autogened
void static_key_slow_inc(void) { abort(); } // TODO --> autogened
void strncpy_from_kernel_nofault(void) { abort(); } // TODO --> autogened
void strncpy_from_user(void) { abort(); } // TODO --> autogened
void strncpy_from_user_nofault(void) { abort(); } // TODO --> autogened
void synchronize_rcu(void) { abort(); } // TODO --> autogened
void sysctl_optmem_max(void) { abort(); } // TODO --> autogened
void sysctl_perf_event_max_stack(void) { abort(); } // TODO --> autogened
void sysctl_rmem_max(void) { abort(); } // TODO --> autogened
void sysctl_wmem_max(void) { abort(); } // TODO --> autogened
void system_wq(void) { abort(); } // TODO --> autogened
void task_storage_map_ops(void) { abort(); } // TODO --> autogened
void tcp_getsockopt(void) { abort(); } // TODO --> autogened
void tcp_hashinfo(void) { abort(); } // TODO --> autogened
void tcp_prot(void) { abort(); } // TODO --> autogened
void tcp_set_congestion_control(void) { abort(); } // TODO --> autogened
void tcp_set_window_clamp(void) { abort(); } // TODO --> autogened
void tcp_setsockopt(void) { abort(); } // TODO --> autogened
void tcp_sock_set_keepidle_locked(void) { abort(); } // TODO --> autogened
void trie_map_ops(void) { abort(); } // TODO --> autogened
void udp_table(void) { abort(); } // TODO --> autogened
void vabits_actual(void) { abort(); } // TODO --> autogened
void vmemdup_user(void) { abort(); } // TODO --> autogened
void vscnprintf(void) { abort(); } // TODO --> autogened
void xdp_convert_zc_to_xdp_frame(void) { abort(); } // TODO --> autogened
void xdp_warn(void) { abort(); } // TODO --> autogened
