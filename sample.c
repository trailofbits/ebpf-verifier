#include <linux/filter.h>
#include <stdio.h>

int main() {
  // printf("size is: %lu\n", sizeof(union bpf_attr));
  printf("filter: %lu\n", sizeof(struct sock_filter));
  return 1;
}
