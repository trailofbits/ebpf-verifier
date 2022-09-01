#ifdef __v4_0__
#include <linux/bpf.h>

struct bpf_prog_type_list;
static struct bpf_prog_type_list tl;

int wrapper_register_sock_filter_ops(void) {
  bpf_register_prog_type(&tl);
  return 0;
}
#endif
