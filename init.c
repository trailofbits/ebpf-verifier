#include <stdlib.h>
#include <linux/filter.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdbool.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "s.skel.h"

extern int init_pseudo_filesys(void);
// extern int real_main(void); // main in the actual bpf loader program

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

  return err;
}
