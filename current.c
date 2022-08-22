#include <stdlib.h>

static struct task_struct *current;

extern int size_of_task_struct(void);
extern void set_audit_context_null(struct task_struct *t);

//  originally a macro from inlude/asm-generic/current.h
struct task_struct *get_current(void) { return current; }

void init_pseudo_task_struct() {
  current = (struct task_struct *)malloc(size_of_task_struct());
  set_audit_context_null(current);
}


