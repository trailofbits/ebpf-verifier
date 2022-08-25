#define __ASM_CURRENT_H
#ifdef __v5_18__
#include <linux/signal.h>
extern struct task_struct *get_current();

#define current get_current()
#endif /* __v5_18__ */
