/* simple_main.c --> calls bpf_check directly with invalid args. */
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>

struct bpf_prog {
  int pages;
};

extern int bpf_check(void * a, union bpf_attr *b, void * c);

int main() {

  struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  prog->pages = 5;

  union bpf_attr at = { 7 };
  bpf_check(&prog, &at, NULL);
  return 0;
}
