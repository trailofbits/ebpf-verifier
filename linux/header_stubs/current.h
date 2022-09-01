#define __ASM_CURRENT_H
#if defined  __v5_18__  || defined __v5_2__
#include <linux/signal.h>
#else
#define __ASM_GENERIC_CURRENT_H
#endif

extern struct task_struct *get_current(void);
#define current get_current()
