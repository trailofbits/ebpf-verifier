// /* simple_main.c --> calls bpf_check directly with invalid args. */

// #include <stddef.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>


// #include <unistd.h>

//#include <linux/bpf.h>
//#include <linux/syscalls.h>

//extern int __sys_bpf(int, void *, int);
//extern int bpf_sys_bpf(int, int, void *, void *, int, int);
//extern long bpf_sys_bpf(u32 cmd, void *attr, u32 attr_size);
extern int bpf_prog_load(void *, void *);

char bpf_log_buf[1024];

// enum bpf_cmd {
// 	BPF_MAP_CREATE,
// 	BPF_MAP_LOOKUP_ELEM,
// 	BPF_MAP_UPDATE_ELEM,
// 	BPF_MAP_DELETE_ELEM,
// 	BPF_MAP_GET_NEXT_KEY,
// 	BPF_PROG_LOAD,
// };

//#define BPF_PROG_LOAD

static int test(void)
{
  // int sock = -1, map_fd, prog_fd, i, key;

  // struct bpf_insn prog[] = {BPF_EXIT_INSN(),};
  // size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  // struct bpf_prog_load_opts opts = {};

  //int prog_fd = __sys_bpf(2, (void *)0, 0);
  //int prog_fd = bpf_sys_bpf(1, 1, (void *)0, (void *)0, 5, 2);
  //int prog_fd = bpf_prog_load((void *)0, (void *)0);
  //printf("FD: %d", prog_fd);
  //close(prog_fd);
  //return prog_fd;
  return 1;
  // prog_fd = bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, "GPL", prog, insns_cnt, &opts);
}

int main() {
  test();
  return 0;
}
