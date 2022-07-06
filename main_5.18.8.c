// /* simple_main.c --> calls bpf_check directly with invalid args. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


// TODO: this definitely won't actually work, but it gives me
// something to pass into bpf_check
struct bpf_prog {
  uint16_t pages;
};

union bpf_attr {
  struct {
    int	map_type;	/* one of enum bpf_map_type */
  };
};

extern int bpf_check(void * a, void *b, void * c);

int main() {
  struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  prog->pages = 5;

  union bpf_attr at = { 7 };
  bpf_check(&prog, &at, NULL);
  //bpf_check(NULL, NULL, NULL);
  return 0;
}
