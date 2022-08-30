#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include "hello.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}


int load() {
  struct hello_bpf *obj;
  struct bpf_program *p;
  const struct bpf_insn *insns;
  int err = 0;

  libbpf_set_print(libbpf_print_fn);

  obj = hello_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open load BPF object. \n");
    return 1;
  }


  p = obj->progs.handle_tp;
  bpf_object__set_kversion(obj->obj, 262144);


  char * log_buf;
  log_buf = malloc(10024);
  if (bpf_program__set_log_buf(p, log_buf, 10000) < 0) {
    fprintf(stderr, "failed to set log buf \n");
    abort();
  }

  insns = bpf_program__insns(p);

  // bpf_map__set_autocreate(obj->maps.rodata, false);
  bpf_program__set_log_level(p, 1);

  // call bpf_object__load directly because 's_bpf__load`
  // invokes bpf_object__load_skeleton which calls bpf_object__load
  // but then doesstuff that doesn't work with the harness.
  // specifically it tries to remmap the maps.
  // see libbpf.c:bpf_object__load_skeleton for details.
  err = bpf_object__load(*obj->skeleton->obj);

  insns = bpf_program__insns(p);

  // free memory allocated by libbpf functions
  hello_bpf__destroy(obj);
  free(log_buf);
  return err;
}
