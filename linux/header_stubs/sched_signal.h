#define _LINUX_SCHED_SIGNAL_H
#include <linux/sched/jobctl.h>

struct pid;
struct task_struct;
struct kernel_siginfo;

extern int fatal_signal_pending(struct task_struct *);
extern int force_sig_info(struct kernel_siginfo *info);
extern bool same_thread_group(struct task_struct *p1, struct task_struct *p2);
extern int send_sig(int sig, struct task_struct *p, int priv);
extern int signal_pending(struct task_struct *);
extern struct pid * task_tgid(struct task_struct *);
