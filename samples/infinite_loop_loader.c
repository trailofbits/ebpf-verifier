#include <stdarg.h>
#include <stdio.h>
#include "infinite_loop.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int load() {
  struct infinite_loop_bpf *obj;
  int err = 0;

  libbpf_set_print(libbpf_print_fn);

  obj = infinite_loop_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open load BPF object. \n");
    return 1;
  }

  // call bpf_object__load directly because 's_bpf__load`
  // invokes bpf_object__load_skeleton which calls bpf_object__load
  // but then doesstuff that doesn't work with the harness.
  // specifically it tries to remmap the maps.
  // see libbpf.c:bpf_object__load_skeleton for details.
  err = bpf_object__load(*obj->skeleton->obj);

  // free memory allocated by libbpf functions
  infinite_loop_bpf__destroy(obj);

  return err;
}
