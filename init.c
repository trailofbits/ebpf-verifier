#include <stdlib.h>


extern int real_main(void); // main in the actual bpf loader program

struct task_struct {
  int test;
  void * audit_context;
};

static struct task_struct *current;

//  originally a macro from inlude/asm-generic/current.h
struct task_struct *get_current(void) { return current; }

// set up the simulated vfs and current task struct
void init(void) {
  current = malloc(sizeof(struct task_struct));
}


int main() {
  init();
  return real_main();
}
