#include "vmlinux.h" // includes basic BPF-related types and constants necessary for using kernel-side BPF APIs (BPF helper function flags) (this should be from uapi or /usr/include)
#include <bpf/bpf_helpers.h> // from libbpf: contains macros, constants, and BPF helper defs (e.g. bpf_get_current_pid_tgid() )

int my_pid = 0;
int cool_pid = 7;

SEC("tracepoint/syscalls/sys_enter_execve") // defines the BPF program that will be loaded into the kernel. Consists of a single function
int handle_tp(void *ctx)
{
	bpf_printk("BPF triggered.%d\n", 5);
	int pid = bpf_get_current_pid_tgid() >> 32;

	int my_num = 897987;
	if (my_pid == pid) {
		return 1;
	} else if (my_num < pid) {
		return 7;
	} else if (pid == cool_pid) {
		return 12;
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
