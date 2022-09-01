#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
	while (0 == 0) {
		bpf_printk("Hello World.\n");
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
