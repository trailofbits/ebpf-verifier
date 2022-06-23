#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int bpf_check(void * a, void * b, void * c);

// TODO: this definitely won't actually work, but it gives me
// something to pass into bpf_check
struct bpf_prog {
  uint16_t pages;
};

int main() {
  printf("hello world\n");
  struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  prog->pages = 5;
  bpf_check(&prog, NULL, NULL);
  return 0;
}
