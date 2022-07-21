// copy of minimal

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h> // includes basic BPF-related types and constants necessary for using kernel-side BPF APIs (BPF helper function flags) (this should be from uapi or /usr/include)
#include <bpf/bpf_helpers.h> // from libbpf: contains macros, constants, and BPF helper defs (e.g. bpf_get_current_pid_tgid() )

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write") // defines the BPF program that will be loaded into the kernel. Consists of a single function
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
