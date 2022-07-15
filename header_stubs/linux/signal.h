// #define _LINUX_SIGNAL_H
// struct task_struct {
// 	struct task_struct 	*real_parent;
// };
// extern void clear_siginfo(kernel_siginfo_t *info); // TODO --> fix params + return
// extern void sigaddset(sigset_t *set, int _sig); // TODO --> fix params + return
#include <linux/signal.h>

#define _LINUX_SCHED_SIGNAL_H
extern int fatal_signal_pending(struct task_struct *p); // TODO --> fix params + return (actually in linux/sched/signal.h)
extern int force_sig_info(struct kernel_siginfo *); // TODO --> fix params + return (in sched/signal.h)
extern bool same_thread_group(struct task_struct *p1, struct task_struct *p2); // TODO --> fix params + return (in sched/signal.h)
extern int send_sig(int, struct task_struct *, int);// TODO --> fix params + return (in sched/signal.h)
extern int signal_pending(struct task_struct *p); // in sched/signal.h
extern struct pid *task_tgid(struct task_struct *task); // TODO --> fix params + return (in sched/signal.h)

#define _LINUX_SCHED_JOBCTL_H
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
extern bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask); // TODO --> fix params + return (in sched/jobctl.h)

#define _LINUX_SCHED_TASK_H
extern void put_task_struct(struct task_struct *t); // TODO --> fix params + return (in sched/task.h)
