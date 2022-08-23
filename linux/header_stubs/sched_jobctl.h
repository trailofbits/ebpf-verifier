#define _LINUX_SCHED_JOBCTL_H
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
extern int force_sig_info(struct kernel_siginfo *); // TODO --> fix params + return (in sched/signal.h)
extern bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask); // TODO --> fix params + return (in sched/jobctl.h)
