#include <stdio.h>
#include <stdlib.h>

extern int bpf_check(void * a, void * b, void * c);

int main() {
  printf("hello world\n");
  bpf_check(NULL, NULL, NULL);
  return 0;
}
