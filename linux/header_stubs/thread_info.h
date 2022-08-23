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

#define SECCOMP -666 // TODO: can't find where this is really defined in linux kernel???
