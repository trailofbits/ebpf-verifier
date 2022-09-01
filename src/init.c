#include <stdlib.h>
#include <stdio.h>

extern void init_pseudo_task_struct(void);

extern void init_ptr_store(void);
extern void destroy_ptr_store(void);

extern int load();

extern struct btf *btf_vmlinux; // this is declared in verifier.c
extern void btf__free(struct btf *btf); // in libbpf btf.c

#ifdef __v4_0__
  extern int wrapper_register_sock_filter_ops(void);
#endif

// set up the pseudo current task struct and the ptr store
void init_harness(void) {
#ifdef HARNESS
  init_ptr_store();
  init_pseudo_task_struct();
  #ifdef __v4_0__
  wrapper_register_sock_filter_ops();
  #endif
#endif
}

int main() {
  int err;

  init_harness();

  err = load(); // attempt to run verifier

  if (err) {
    fprintf(stderr, "Failed to load BPF object %d.\n", err);
  } else {
    fprintf(stdout, "BPF object loaded successfully!\n");
  }

#ifdef HARNESS
  destroy_ptr_store();
  #if defined __v5_18__ || defined __v5_2__
  if (btf_vmlinux) {
    btf__free(btf_vmlinux);
  }
  #endif /* __v5_18__ */
#endif

  return err;
}
