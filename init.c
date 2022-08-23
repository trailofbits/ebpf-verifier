#include <bpf/libbpf.h>
#include "src/s.skel.h"

extern void init_pseudo_task_struct(void);
extern void init_ptr_store(void);
extern void destroy_ptr_store(void);

extern struct btf *btf_vmlinux; // this is declared in verifier.c
extern void btf__free(struct btf *btf); // in libbpf btf.c

// set up the simulated vfs and current task struct
void init(void) {
#ifdef HARNESS
  init_ptr_store();
  init_pseudo_task_struct();
#endif
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int main() {
  init();

  struct s_bpf *obj;
  int err = 0;

  libbpf_set_print(libbpf_print_fn);

  char *path = "/home/parallels/ebpf-verifier/linux/vmlinux.h";

  struct bpf_object_open_opts opts = {
    .sz = 0,
    .btf_custom_path = path,
  };

  opts.sz = sizeof(opts);

  obj = s_bpf__open_opts(&opts);
  if (!obj) {
    fprintf(stderr, "failed to open and/or load BPF object\n");
    return 1;
  }

  err = bpf_object__load(*obj->skeleton->obj);
  if (err) {
    fprintf(stderr, "failed to load BPF object %d\n", err);
  } else {
    fprintf(stdout, "loaded successfully!\n");
  }

#ifdef HARNESS
  destroy_ptr_store();
  if (btf_vmlinux) {
    btf__free(btf_vmlinux);
  }
#endif
  s_bpf__destroy(obj);
  return err;
}
