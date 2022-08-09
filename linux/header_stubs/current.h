#define __ASM_CURRENT_H

#include <linux/signal.h>
extern struct task_struct *get_current(void);

#define current get_current()
