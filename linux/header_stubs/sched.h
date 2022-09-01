#include <linux/sched.h>

inline int size_of_task_struct(void) { return sizeof(struct task_struct); }
inline void set_audit_context_null(struct task_struct *t) {t->audit_context = NULL; }
