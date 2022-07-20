#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	bpf_printk("Hello world!\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
