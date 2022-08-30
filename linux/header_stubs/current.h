#define __ASM_CURRENT_H
#ifdef __v5_18__
#include <linux/signal.h>
#else
#define __ASM_GENERIC_CURRENT_H
#endif /* __v5_18__ */

extern struct task_struct *get_current(void);
#define current get_current()
