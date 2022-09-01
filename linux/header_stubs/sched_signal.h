#define _LINUX_SCHED_SIGNAL_H
#if defined  __v5_18__  || defined __v5_2__
#include <linux/sched/jobctl.h>

struct pid;
struct task_struct;
struct kernel_siginfo;

#ifndef __v5_2__
extern int force_sig_info(struct kernel_siginfo *info);
#else
extern void force_sig(int, struct task_struct *);
extern int force_sig_info(int, struct kernel_siginfo *, struct task_struct *);
extern unsigned long rlimit(unsigned int limit);
#endif

// extern void force_sig(int, struct task_struct *);
extern int fatal_signal_pending(struct task_struct *);
extern bool same_thread_group(struct task_struct *p1, struct task_struct *p2);
extern int send_sig(int sig, struct task_struct *p, int priv);
extern int signal_pending(struct task_struct *);
extern struct pid * task_tgid(struct task_struct *);
#endif
