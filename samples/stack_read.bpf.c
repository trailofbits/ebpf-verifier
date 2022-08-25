// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
  int my_stack_var;
  char hello_string[5] = "abcde";
  my_stack_var = 5555;
  bpf_printk("%s: %x", hello_string, &my_stack_var);
	return 0;
}
