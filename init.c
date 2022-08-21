#include <stdlib.h>
#include <linux/filter.h>

extern int init_pseudo_filesys(void);
extern int real_main(void); // main in the actual bpf loader program

struct my_task_struct {
  int test;
  void * audit_context;
};

struct task_struct *current;

//  originally a macro from inlude/asm-generic/current.h
struct task_struct *get_current(void) { return current; }

// set up the simulated vfs and current task struct
void init(void) {
  init_pseudo_filesys();
  current = malloc(sizeof(struct my_task_struct));
}

int main() {
  init();
  return real_main();
}
