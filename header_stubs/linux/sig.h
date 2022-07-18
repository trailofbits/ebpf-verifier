#define _LINUX_SCHED_SIGNAL_H
extern int fatal_signal_pending(struct task_struct *p); // TODO --> fix params + return (actually in linux/sched/signal.h)
extern int same_thread_group(struct task_struct *p1, struct task_struct *p2); // TODO --> fix params + return (in sched/signal.h)
extern int send_sig(int, struct task_struct *, int);// TODO --> fix params + return (in sched/signal.h)
extern struct pid *task_tgid(struct task_struct *task); // TODO --> fix params + return (in sched/signal.h)
extern int signal_pending(struct task_struct *p); // in sched/signal.h

#define _LINUX_SCHED_JOBCTL_H
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
extern int force_sig_info(struct kernel_siginfo *); // TODO --> fix params + return (in sched/signal.h)
extern bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask); // TODO --> fix params + return (in sched/jobctl.h)

#define _LINUX_THREAD_INFO_H
#include <asm/thread_info.h>
#include <linux/restart_block.h>
extern int tif_need_resched(void);
#define current_thread_info() ((struct thread_info *)current)

extern int test_syscall_work(int);
extern void set_ti_thread_flag(struct thread_info *, int);
extern void clear_ti_thread_flag(struct thread_info *, int);
extern void update_ti_thread_flag(struct thread_info *, int, int);
extern int test_and_clear_ti_thread_flag(struct thread_info *, int);
extern int test_ti_thread_flag(struct thread_info *, int);
extern int test_and_set_ti_thread_flag(struct thread_info *, int);
extern int check_copy_size(const void *addr, size_t bytes, bool is_source);
extern int test_thread_flag(int);
extern void check_object_size(const void *ptr, unsigned long n,
					bool to_user);

#define SECCOMP -666 // can't find where this is really defined in linux kernel???
