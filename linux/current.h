#define __ASM_CURRENT_H

struct task_struct;

static __always_inline struct task_struct *get_current(void) {
  return (struct task_struct *) NULL;
}

#define current get_current()
