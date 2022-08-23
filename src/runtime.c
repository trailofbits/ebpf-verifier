#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
// #include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "memory.h"

#define ZERO_SIZE_PTR ((void *)16)

// TODO: improve idr replacement and move to its own file. (really fragile and bad right now)
// Really basic replacement for idr.
#define IDS_SIZE 100
#define BASE_ID 3
static int next_id = BASE_ID;
static void * ids[IDS_SIZE];

int idr_alloc_cyclic(void *idr, void *ptr, int start, int end, unsigned int flags) {
	ids[next_id - BASE_ID] = ptr;
	return next_id++;
}

void *idr_find(void *idr, unsigned long id) { return ids[id - BASE_ID]; }

void idr_get_next(void) { abort(); }
void idr_preload(void) { return; }
void *idr_remove(void *idr, unsigned long id) { return ids[id - BASE_ID]; } // doesn't actually remove at the moment

void migrate_disable(void) { return; }
void migrate_enable(void) { return; }

void __fdget(void) {abort();}


// defined in kernel/trace/trace_events.c --> enables trace events (set to always success)
int trace_set_clr_event(const char *system, const char *event, int set) { return 0; }



void _raw_spin_lock(void) { return; }
void _raw_spin_lock_bh(void) { return; }
void _raw_spin_lock_irqsave(void) { return; }
void _raw_spin_unlock(void) { return; }
void _raw_spin_unlock_bh(void) { return; }
void _raw_spin_unlock_irqrestore(void) { return; }

// void perf_event_array_map_ops(void) { abort(); }
void perf_event_bpf_event(void) { }
void perf_event_free_bpf_prog(void) { abort(); }
void perf_event_get(void) { abort(); }
void perf_event_set_bpf_prog(void) { abort(); }
void perf_get_event(void) { abort(); }

void audit_enabled(void) { return; }
void audit_log_end(void) { return; }
void audit_log_format(void) { return; }
void audit_log_start(void) { return; }

// from stubbing out atomic-instrumented.h
void atomic64_add(void) { return; } // TODO --> autogened
void atomic64_dec(void) { return; } // TODO --> autogened
void atomic64_dec_and_test(void) { abort(); } // TODO --> autogened
void atomic64_fetch_add_unless(void) { abort(); } // TODO --> autogened
void atomic64_inc(void) { return; } // TODO --> autogened
long atomic64_read(const long *ptr) { return *ptr; } // TODO --> autogened
void atomic64_set(void) { return; } // TODO --> autogened
void atomic64_sub_return(void) { abort(); } // TODO --> autogened
void atomic_fetch_sub_release(void) { abort(); } // TODO --> autogened
void atomic_long_add(void) { abort(); } // TODO --> autogened
void atomic_long_inc(void) { abort(); } // TODO --> autogened
void atomic_long_read(void) { abort(); } // TODO --> autogened
void atomic_long_sub_and_test(void) { abort(); } // TODO --> autogened

void *get_mem_cgroup_from_mm(void * p) { return NULL; }


struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err) {return fp;}
void bpf_prog_kallsyms_add(struct bpf_prog *fp) {}

// TODO: modify this so that custom capabilities can be specified
// and so that we can record what functions are asking about which
// capabilities.
bool capable(int cap) { return true; } // always true for test harness

// originally a macro in include/linux/thread_info.h
bool tif_need_resched(void) {return false;}

// originally function from include/linux/sched/signal.h
int signal_pending(void *p) { return false; }

// include/linux/sched/user.h
void free_uid(void * p) { return; }


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



// originally a macro in include/linux/mutex.h
void __mutex_init(void) { return; }

// TODO: any need for real locks when verifying within harness?
void mutex_lock(void) { return; }
void mutex_unlock(void) { return; }

// originally decl in include/linux/security.h
int security_bpf_prog_alloc(void *aux) { return 0; }
int security_bpf(int cmd, void *attr, unsigned int size) { return 0;}
int security_bpf_map(void *map, unsigned int fmode) { return 0;}
int security_bpf_map_alloc(void *map) { return 0;}
void security_bpf_map_free(void *map) { return; }
int security_bpf_prog(void *prog) { return 0; }
void security_bpf_prog_free(void *aux) { return; }
void security_locked_down(void) { abort(); }

// include/linux/cred.h
struct user_struct *get_current_user() { return NULL; }

// orig. in lib/vsprintf.c
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args) {
	// int i;
	// i = scnprintf(buf, size, fmt, args);
	// return i;
	return 0;
}
size_t ksize(const void *p) { return 0; }



void queue_work_on(void) { return; }

void __rcu_read_lock(void) { return; }
void __rcu_read_unlock(void) { return; }




// TODO: look at below functions and determine how to stub out or include
// actual kernel function or assert that they will never run because they
// are not actually part of the verifier.
// TODO: make sure all of the "functions" are actually supposed to be functions
// they were autogenerated from linking errors. So in some cases they may
// supposed to be a global struct or macro or such. Can lead to very
// annoying bugs.
void ___pskb_trim(void) { abort(); } // TODO --> autogened
void ___ratelimit(void) { abort(); } // TODO --> autogened
void __arch_copy_from_user(void) { abort(); } // TODO --> autogened
void __arch_copy_to_user(void) { abort(); } // TODO --> autogened
void __bitmap_clear(void) { abort(); } // TODO --> autogened
void __bitmap_set(void) { abort(); } // TODO --> autogened
void __bitmap_weight(void) { abort(); } // TODO --> autogened
void __cpu_online_mask(void) { abort(); } // TODO --> autogened
void __cpu_possible_mask(void) { abort(); } // TODO --> autogened
void __dev_get_by_index(void) { abort(); } // TODO --> autogened
void __do_once_done(void) { abort(); } // TODO --> autogened
void __do_once_start(void) { abort(); } // TODO --> autogened
void __free_pages(void) { abort(); } // TODO --> autogened
void __fs_parse(void) { abort(); } // TODO --> autogened
void __inet6_lookup_established(void) { abort(); } // TODO --> autogened
void __inet_bind(void) { abort(); } // TODO --> autogened
void __inet_lookup_established(void) { abort(); } // TODO --> autogened
void __inet_lookup_listener(void) { abort(); } // TODO --> autogened
void __init_waitqueue_head(void) { abort(); } // TODO --> autogened
void __ipv6_addr_type(void) { abort(); } // TODO --> autogened
void __local_bh_enable_ip(void) { abort(); } // TODO --> autogened
void __mmap_lock_do_trace_acquire_returned(void) { abort(); } // TODO --> autogened
void __mmap_lock_do_trace_released(void) { abort(); } // TODO --> autogened
void __mmap_lock_do_trace_start_locking(void) { abort(); } // TODO --> autogened
void __module_address(void) { abort(); } // TODO --> autogened
void __module_text_address(void) { abort(); } // TODO --> autogened
void __neigh_create(void) { abort(); } // TODO --> autogened
void __per_cpu_offset(void) { abort(); } // TODO --> autogened
void __pskb_pull_tail(void) { abort(); } // TODO --> autogened
void __put_net(void) { abort(); } // TODO --> autogened
void __put_page(void) { abort(); } // TODO --> autogened
void __put_task_struct(void) { abort(); } // TODO --> autogened
void __request_module(void) { abort(); } // TODO --> autogened
void __rht_bucket_nested(void) { abort(); } // TODO --> autogened
void __seq_open_private(void) { abort(); } // TODO --> autogened
void __sk_mem_reclaim(void) { abort(); } // TODO --> autogened
void __skb_get_hash(void) { abort(); } // TODO --> autogened
void __sock_gen_cookie(void) { abort(); } // TODO --> autogened
void __start__bpf_raw_tp(void) { abort(); } // TODO --> autogened
void __stop__bpf_raw_tp(void) { abort(); } // TODO --> autogened
void __sw_hweight64(void) { abort(); } // TODO --> autogened
void __task_pid_nr_ns(void) { abort(); } // TODO --> autogened
void __tcp_send_ack(void) { abort(); } // TODO --> autogened
void __trace_trigger_soft_disabled(void) { abort(); } // TODO --> autogened
void __tracepoint_mmap_lock_acquire_returned(void) { abort(); } // TODO --> autogened
void __tracepoint_mmap_lock_released(void) { abort(); } // TODO --> autogened
void __tracepoint_mmap_lock_start_locking(void) { abort(); } // TODO --> autogened
void __udp4_lib_lookup(void) { abort(); } // TODO --> autogened
void __usecs_to_jiffies(void) { abort(); } // TODO --> autogened
void __wake_up(void) { abort(); } // TODO --> autogened
void __warn_printk(void) { abort(); } // TODO --> autogened
void __xdp_build_skb_from_frame(void) { abort(); } // TODO --> autogened
void __xdp_return(void) { abort(); } // TODO --> autogened
void __xdp_rxq_info_reg(void) { abort(); } // TODO --> autogened
void _parse_integer(void) { abort(); } // TODO --> autogened
void _parse_integer_fixup_radix(void) { abort(); } // TODO --> autogened
void _printk(void) { abort(); } // TODO --> autogened
void _raw_spin_trylock(void) { abort(); } // TODO --> autogened
void _raw_write_lock_bh(void) { abort(); } // TODO --> autogened
void _raw_write_unlock_bh(void) { abort(); } // TODO --> autogened
void access_process_vm(void) { abort(); } // TODO --> autogened
void arm64_use_ng_mappings(void) { abort(); } // TODO --> autogened
void arp_tbl(void) { abort(); } // TODO --> autogened
void bin2hex(void) { abort(); } // TODO --> autogened
void bitmap_find_next_zero_area_off(void) { abort(); } // TODO --> autogened
void bpf_core_calc_relo_insn(void) { abort(); } // TODO --> autogened
void bpf_core_patch_insn(void) { abort(); } // TODO --> autogened
void bpf_flow_dissect(void) { abort(); } // TODO --> autogened
void bpf_get_kprobe_info(void) { abort(); } // TODO --> autogened
void bpf_get_uprobe_info(void) { abort(); } // TODO --> autogened
void bpf_prog_run_generic_xdp(void) { abort(); } // TODO --> autogened
void bpf_xdp_link_attach(void) { abort(); } // TODO --> autogened
void bstr_printf(void) { abort(); } // TODO --> autogened
void build_id_parse(void) { abort(); } // TODO --> autogened
void build_skb(void) { abort(); } // TODO --> autogened
void call_rcu(void) { abort(); } // TODO --> autogened
void call_rcu_tasks(void) { abort(); } // TODO --> autogened
void call_rcu_tasks_trace(void) { abort(); } // TODO --> autogened
void cgroup_get_from_fd(void) { abort(); } // TODO --> autogened
void cgroup_mutex(void) { abort(); } // TODO --> autogened
void check_zeroed_user(void) { abort(); } // TODO --> autogened
void close_fd(void) { abort(); } // TODO --> autogened
void consume_skb(void) { abort(); } // TODO --> autogened
void copy_from_kernel_nofault(void) { abort(); } // TODO --> autogened
void copy_from_user_nofault(void) { abort(); } // TODO --> autogened
void copy_to_user_nofault(void) { abort(); } // TODO --> autogened
void cpu_hwcap_keys(void) { abort(); } // TODO --> autogened
void cpu_number(void) { abort(); } // TODO --> autogened
void cpumask_next(void) { abort(); } // TODO --> autogened
void crash_get_memory_size(void) { abort(); } // TODO --> autogened
void crash_shrink_memory(void) { abort(); } // TODO --> autogened
void create_proc_profile(void) { abort(); } // TODO --> autogened
void css_next_descendant_pre(void) { abort(); } // TODO --> autogened
void csum_partial(void) { abort(); } // TODO --> autogened
void current_cred(void) { abort(); } // TODO --> autogened
void current_kprobe(void) { abort(); } // TODO --> autogened
void current_time(void) { abort(); } // TODO --> autogened
void current_umask(void) { abort(); } // TODO --> autogened
void d_instantiate(void) { abort(); } // TODO --> autogened
void d_path(void) { abort(); } // TODO --> autogened
void dev_forward_skb_nomtu(void) { abort(); } // TODO --> autogened
void dev_get_by_index(void) { abort(); } // TODO --> autogened
void dev_get_by_index_rcu(void) { abort(); } // TODO --> autogened
void dev_get_by_name(void) { abort(); } // TODO --> autogened
void dev_queue_xmit(void) { abort(); } // TODO --> autogened
void done_path_create(void) { abort(); } // TODO --> autogened
void down_read(void) { abort(); } // TODO --> autogened
void down_read_killable(void) { abort(); } // TODO --> autogened
void down_read_trylock(void) { abort(); } // TODO --> autogened
void down_write(void) { abort(); } // TODO --> autogened
void dput(void) { abort(); } // TODO --> autogened
void dst_release(void) { abort(); } // TODO --> autogened
void enter_syscall_print_funcs(void) { abort(); } // TODO --> autogened
void eth_type_trans(void) { abort(); } // TODO --> autogened
void event_class_syscall_enter(void) { abort(); } // TODO --> autogened
void event_class_syscall_exit(void) { abort(); } // TODO --> autogened
void exit_syscall_print_funcs(void) { abort(); } // TODO --> autogened
void fd_install(void) { abort(); } // TODO --> autogened
void fget_task(void) { abort(); } // TODO --> autogened
void fib_select_path(void) { abort(); } // TODO --> autogened
void fib_table_lookup(void) { abort(); } // TODO --> autogened
void file_caps_enabled(void) { abort(); } // TODO --> autogened
void find_ge_pid(void) { abort(); } // TODO --> autogened
void find_vm_area(void) { abort(); } // TODO --> autogened
void find_vma(void) { abort(); } // TODO --> autogened
void find_vpid(void) { abort(); } // TODO --> autogened
void flow_dissector_bpf_prog_attach_check(void) { abort(); } // TODO --> autogened
void free_inode_nonrcu(void) { abort(); } // TODO --> autogened
void from_kgid(void) { abort(); } // TODO --> autogened
void from_kuid(void) { abort(); } // TODO --> autogened
void from_kuid_munged(void) { abort(); } // TODO --> autogened
void fs_kobj(void) { abort(); } // TODO --> autogened
void fs_param_is_u32(void) { abort(); } // TODO --> autogened
void generic_delete_inode(void) { abort(); } // TODO --> autogened
void generic_xdp_tx(void) { abort(); } // TODO --> autogened
void get_callchain_buffers(void) { abort(); } // TODO --> autogened
void get_callchain_entry(void) { abort(); } // TODO --> autogened
void get_net_ns_by_fd(void) { abort(); } // TODO --> autogened
void get_net_ns_by_id(void) { abort(); } // TODO --> autogened
void get_next_ino(void) { abort(); } // TODO --> autogened
void get_perf_callchain(void) { abort(); } // TODO --> autogened
void get_pid_task(void) { abort(); } // TODO --> autogened
void get_random_u32(void) { abort(); } // TODO --> autogened
void get_tree_nodev(void) { abort(); } // TODO --> autogened
void get_unused_fd_flags(void) { abort(); } // TODO --> autogened
void gic_nonsecure_priorities(void) { abort(); } // TODO --> autogened
void group_send_sig_info(void) { abort(); } // TODO --> autogened
void hrtimer_cancel(void) { abort(); } // TODO --> autogened
void hrtimer_init(void) { abort(); } // TODO --> autogened
void hrtimer_start_range_ns(void) { abort(); } // TODO --> autogened
void inc_nlink(void) { abort(); } // TODO --> autogened
void inet6_lookup_listener(void) { abort(); } // TODO --> autogened
void inet_proto_csum_replace4(void) { abort(); } // TODO --> autogened
void inet_proto_csum_replace_by_diff(void) { abort(); } // TODO --> autogened
void init_net(void) { abort(); } // TODO --> autogened
void init_pid_ns(void) { abort(); } // TODO --> autogened
void init_user_ns(void) { abort(); } // TODO --> autogened
void inode_init_owner(void) { abort(); } // TODO --> autogened
void inode_permission(void) { abort(); } // TODO --> autogened
void int_active_memcg(void) { abort(); } // TODO --> autogened
void ip_mtu_from_fib_result(void) { abort(); } // TODO --> autogened
void ip_route_output_flow(void) { abort(); } // TODO --> autogened
void ipv6_stub(void) { abort(); } // TODO --> autogened
void irq_work_queue(void) { abort(); } // TODO --> autogened
void is_skb_forwardable(void) { abort(); } // TODO --> autogened
void jiffies(void) { abort(); } // TODO --> autogened
void kallsyms_lookup_name(void) { abort(); } // TODO --> autogened
void kallsyms_show_value(void) { abort(); } // TODO --> autogened
void kern_path(void) { abort(); } // TODO --> autogened
void kexec_crash_loaded(void) { abort(); } // TODO --> autogened
void kexec_image(void) { abort(); } // TODO --> autogened
void kfree_skb_reason(void) { abort(); } // TODO --> autogened
void kill_litter_super(void) { abort(); } // TODO --> autogened
void kobject_create_and_add(void) { abort(); } // TODO --> autogened
void kobject_put(void) { abort(); } // TODO --> autogened
void kstrdup(void) { abort(); } // TODO --> autogened
void kstrtoint(void) { abort(); } // TODO --> autogened
void kstrtoull(void) { abort(); } // TODO --> autogened
void kthread_bind(void) { abort(); } // TODO --> autogened
void kthread_create_on_node(void) { abort(); } // TODO --> autogened
void kthread_should_stop(void) { abort(); } // TODO --> autogened
void kthread_stop(void) { abort(); } // TODO --> autogened
void ktime_get_boot_fast_ns(void) { abort(); } // TODO --> autogened
void ktime_get_coarse_ts64(void) { abort(); } // TODO --> autogened
void ktime_get_mono_fast_ns(void) { abort(); } // TODO --> autogened
void lock_sock_nested(void) { abort(); } // TODO --> autogened
void lockref_get(void) { abort(); } // TODO --> autogened
void lookup_one_len(void) { abort(); } // TODO --> autogened
void make_kuid(void) { abort(); } // TODO --> autogened
void memdup_user(void) { abort(); } // TODO --> autogened
void memstart_addr(void) { abort(); } // TODO --> autogened
void metadata_dst_alloc_percpu(void) { abort(); } // TODO --> autogened
void metadata_dst_free_percpu(void) { abort(); } // TODO --> autogened
void module_alloc(void) { abort(); } // TODO --> autogened
void module_memfree(void) { abort(); } // TODO --> autogened
void module_put(void) { abort(); } // TODO --> autogened
void msg_zerocopy_callback(void) { abort(); } // TODO --> autogened
void mutex_is_locked(void) { abort(); } // TODO --> autogened
void net_ratelimit(void) { abort(); } // TODO --> autogened
void netdev_core_stats_alloc(void) { abort(); } // TODO --> autogened
void netdev_master_upper_dev_get_rcu(void) { abort(); } // TODO --> autogened
void netdev_upper_get_next_dev_rcu(void) { abort(); } // TODO --> autogened
void netdev_warn(void) { abort(); } // TODO --> autogened
void netif_receive_skb_list(void) { abort(); } // TODO --> autogened
void netif_rx(void) { abort(); } // TODO --> autogened
void new_inode(void) { abort(); } // TODO --> autogened
void nla_find(void) { abort(); } // TODO --> autogened
void nla_put(void) { abort(); } // TODO --> autogened
void nla_reserve_64bit(void) { abort(); } // TODO --> autogened
void no_llseek(void) { abort(); } // TODO --> autogened
void node_states(void) { abort(); } // TODO --> autogened
void nr_cpu_ids(void) { abort(); } // TODO --> autogened
void nr_node_ids(void) { abort(); } // TODO --> autogened
void ns_get_path_cb(void) { abort(); } // TODO --> autogened
void ns_match(void) { abort(); } // TODO --> autogened
void numa_node(void) { abort(); } // TODO --> autogened
void overflowuid(void) { abort(); } // TODO --> autogened
void paddr_vmcoreinfo_note(void) { abort(); } // TODO --> autogened
void page_pool_alloc_pages(void) { abort(); } // TODO --> autogened
void page_pool_create(void) { abort(); } // TODO --> autogened
void page_pool_destroy(void) { abort(); } // TODO --> autogened
void path_put(void) { abort(); } // TODO --> autogened
void percpu_ref_exit(void) { abort(); } // TODO --> autogened
void percpu_ref_init(void) { abort(); } // TODO --> autogened
void percpu_ref_is_zero(void) { abort(); } // TODO --> autogened
void percpu_ref_kill_and_confirm(void) { abort(); } // TODO --> autogened
void perf_event_ksymbol(void) { abort(); } // TODO --> autogened
void perf_event_output(void) { abort(); } // TODO --> autogened
void perf_event_read_local(void) { abort(); } // TODO --> autogened
void perf_trace_buf_alloc(void) { abort(); } // TODO --> autogened
void perf_trace_run_bpf_submit(void) { abort(); } // TODO --> autogened
void pid_nr_ns(void) { abort(); } // TODO --> autogened
void pid_task(void) { abort(); } // TODO --> autogened
void pidfd_get_pid(void) { abort(); } // TODO --> autogened
void prandom_seed_full_state(void) { abort(); } // TODO --> autogened
void prandom_u32_state(void) { abort(); } // TODO --> autogened
void preempt_schedule(void) { abort(); } // TODO --> autogened
void preempt_schedule_notrace(void) { abort(); } // TODO --> autogened
void prof_on(void) { abort(); } // TODO --> autogened
void profile_init(void) { abort(); } // TODO --> autogened
void profile_setup(void) { abort(); } // TODO --> autogened
void pskb_expand_head(void) { abort(); } // TODO --> autogened
void put_callchain_buffers(void) { abort(); } // TODO --> autogened
void put_callchain_entry(void) { abort(); } // TODO --> autogened
void put_pid(void) { abort(); } // TODO --> autogened
void put_pid_ns(void) { abort(); } // TODO --> autogened
void put_task_stack(void) { abort(); } // TODO --> autogened
void put_unused_fd(void) { abort(); } // TODO --> autogened
void queued_spin_lock_slowpath(void) { abort(); } // TODO --> autogened
void rb_erase(void) { abort(); } // TODO --> autogened
void rb_insert_color(void) { abort(); } // TODO --> autogened
void rcu_barrier(void) { abort(); } // TODO --> autogened
void rcu_read_unlock_trace_special(void) { abort(); } // TODO --> autogened
void refcount_warn_saturate(void) { abort(); } // TODO --> autogened
void register_filesystem(void) { abort(); } // TODO --> autogened
void register_module_notifier(void) { abort(); } // TODO --> autogened
void register_netdevice_notifier(void) { abort(); } // TODO --> autogened
void register_pernet_subsys(void) { abort(); } // TODO --> autogened
void release_sock(void) { abort(); } // TODO --> autogened
void remap_vmalloc_range(void) { abort(); } // TODO --> autogened
void reuseport_attach_prog(void) { abort(); } // TODO --> autogened
void reuseport_lock(void) { abort(); } // TODO --> autogened
void rhashtable_init(void) { abort(); } // TODO --> autogened
void rhashtable_insert_slow(void) { abort(); } // TODO --> autogened
void rht_bucket_nested(void) { abort(); } // TODO --> autogened
void rht_bucket_nested_insert(void) { abort(); } // TODO --> autogened
void rtnl_is_locked(void) { abort(); } // TODO --> autogened
void rtnl_lock(void) { abort(); } // TODO --> autogened
void rtnl_unlock(void) { abort(); } // TODO --> autogened
void sched_clock(void) { abort(); } // TODO --> autogened
void schedule(void) { abort(); } // TODO --> autogened
void search_extable(void) { abort(); } // TODO --> autogened
void seq_bprintf(void) { abort(); } // TODO --> autogened
void seq_open(void) { abort(); } // TODO --> autogened
void seq_printf(void) { abort(); } // TODO --> autogened
void seq_puts(void) { abort(); } // TODO --> autogened
void seq_read(void) { abort(); } // TODO --> autogened
void seq_release(void) { abort(); } // TODO --> autogened
void seq_release_private(void) { abort(); } // TODO --> autogened
void seq_vprintf(void) { abort(); } // TODO --> autogened
void seq_write(void) { abort(); } // TODO --> autogened
void set_memory_nx(void) { abort(); } // TODO --> autogened
void set_memory_ro(void) { abort(); } // TODO --> autogened
void set_memory_rw(void) { abort(); } // TODO --> autogened
void set_memory_x(void) { abort(); } // TODO --> autogened
void simple_dir_operations(void) { abort(); } // TODO --> autogened
void simple_fill_super(void) { abort(); } // TODO --> autogened
void simple_link(void) { abort(); } // TODO --> autogened
void simple_lookup(void) { abort(); } // TODO --> autogened
void simple_rename(void) { abort(); } // TODO --> autogened
void simple_rmdir(void) { abort(); } // TODO --> autogened
void simple_statfs(void) { abort(); } // TODO --> autogened
void simple_symlink_inode_operations(void) { abort(); } // TODO --> autogened
void simple_unlink(void) { abort(); } // TODO --> autogened
void sk_alloc(void) { abort(); } // TODO --> autogened
void sk_free(void) { abort(); } // TODO --> autogened
void sk_psock_drop(void) { abort(); } // TODO --> autogened
void sk_psock_init(void) { abort(); } // TODO --> autogened
void sk_psock_link_pop(void) { abort(); } // TODO --> autogened
void sk_psock_start_verdict(void) { abort(); } // TODO --> autogened
void sk_psock_stop(void) { abort(); } // TODO --> autogened
void sk_psock_stop_verdict(void) { abort(); } // TODO --> autogened
void skb_clone(void) { abort(); } // TODO --> autogened
void skb_copy_ubufs(void) { abort(); } // TODO --> autogened
void skb_ensure_writable(void) { abort(); } // TODO --> autogened
void skb_expand_head(void) { abort(); } // TODO --> autogened
void skb_get_poff(void) { abort(); } // TODO --> autogened
void skb_gso_validate_network_len(void) { abort(); } // TODO --> autogened
void skb_pull(void) { abort(); } // TODO --> autogened
void skb_push(void) { abort(); } // TODO --> autogened
void skb_scrub_packet(void) { abort(); } // TODO --> autogened
void skb_trim(void) { abort(); } // TODO --> autogened
void skb_vlan_pop(void) { abort(); } // TODO --> autogened
void skb_vlan_push(void) { abort(); } // TODO --> autogened
void skbuff_head_cache(void) { abort(); } // TODO --> autogened
void smp_call_function_single(void) { abort(); } // TODO --> autogened
void sock_bindtoindex(void) { abort(); } // TODO --> autogened
void sock_from_file(void) { abort(); } // TODO --> autogened
void sock_gen_put(void) { abort(); } // TODO --> autogened
void sock_init_data(void) { abort(); } // TODO --> autogened
void sock_pfree(void) { abort(); } // TODO --> autogened
void sockfd_lookup(void) { abort(); } // TODO --> autogened
void softnet_data(void) { abort(); } // TODO --> autogened
void stack_trace_save_tsk(void) { abort(); } // TODO --> autogened
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
void sysfs_create_bin_file(void) { abort(); } // TODO --> autogened
void sysfs_create_group(void) { abort(); } // TODO --> autogened
void sysfs_create_mount_point(void) { abort(); } // TODO --> autogened
void sysfs_remove_bin_file(void) { abort(); } // TODO --> autogened
void sysfs_remove_group(void) { abort(); } // TODO --> autogened
void sysfs_remove_mount_point(void) { abort(); } // TODO --> autogened
void system_wq(void) { abort(); } // TODO --> autogened
void task_active_pid_ns(void) { abort(); } // TODO --> autogened
void task_lookup_next_fd_rcu(void) { abort(); } // TODO --> autogened
void tcp_ca_find(void) { abort(); } // TODO --> autogened
void tcp_getsockopt(void) { abort(); } // TODO --> autogened
void tcp_hashinfo(void) { abort(); } // TODO --> autogened
void tcp_prot(void) { abort(); } // TODO --> autogened
void tcp_register_congestion_control(void) { abort(); } // TODO --> autogened
void tcp_set_congestion_control(void) { abort(); } // TODO --> autogened
void tcp_set_window_clamp(void) { abort(); } // TODO --> autogened
void tcp_setsockopt(void) { abort(); } // TODO --> autogened
void tcp_sock_set_keepidle_locked(void) { abort(); } // TODO --> autogened
void tcp_unregister_congestion_control(void) { abort(); } // TODO --> autogened
void touch_atime(void) { abort(); } // TODO --> autogened
void trace_event_buffer_commit(void) { abort(); } // TODO --> autogened
void trace_event_buffer_reserve(void) { abort(); } // TODO --> autogened
void trace_event_printf(void) { abort(); } // TODO --> autogened
void trace_event_raw_init(void) { abort(); } // TODO --> autogened
void trace_event_reg(void) { abort(); } // TODO --> autogened
void trace_handle_return(void) { abort(); } // TODO --> autogened
void trace_kprobe_error_injectable(void) { abort(); } // TODO --> autogened
void trace_kprobe_on_func_entry(void) { abort(); } // TODO --> autogened
void trace_print_symbols_seq(void) { abort(); } // TODO --> autogened
void trace_raw_output_prep(void) { abort(); } // TODO --> autogened
void tracepoint_probe_register_prio_may_exist(void) { abort(); } // TODO --> autogened
void tracepoint_probe_unregister(void) { abort(); } // TODO --> autogened
void try_module_get(void) { abort(); } // TODO --> autogened
void udp_table(void) { abort(); } // TODO --> autogened
void uevent_seqnum(void) { abort(); } // TODO --> autogened
void up_read(void) { abort(); } // TODO --> autogened
void up_write(void) { abort(); } // TODO --> autogened
void user_path_at_empty(void) { abort(); } // TODO --> autogened
void user_path_create(void) { abort(); } // TODO --> autogened
void vabits_actual(void) { abort(); } // TODO --> autogened
void vfs_mkobj(void) { abort(); } // TODO --> autogened
void vfs_parse_fs_param_source(void) { abort(); } // TODO --> autogened
void vmap(void) { abort(); } // TODO --> autogened
void vmemdup_user(void) { abort(); } // TODO --> autogened
void vunmap(void) { abort(); } // TODO --> autogened
void wake_up_process(void) { abort(); } // TODO --> autogened
void within_error_injection_list(void) { abort(); } // TODO --> autogened
void xdp_convert_zc_to_xdp_frame(void) { abort(); } // TODO --> autogened
void xdp_reg_mem_model(void) { abort(); } // TODO --> autogened
void xdp_return_buff(void) { abort(); } // TODO --> autogened
void xdp_return_frame(void) { abort(); } // TODO --> autogened
void xdp_return_frame_rx_napi(void) { abort(); } // TODO --> autogened
void xdp_rxq_info_is_reg(void) { abort(); } // TODO --> autogened
void xdp_unreg_mem_model(void) { abort(); } // TODO --> autogened
void xdp_warn(void) { abort(); } // TODO --> autogened
void xdpf_clone(void) { abort(); } // TODO --> autogened
