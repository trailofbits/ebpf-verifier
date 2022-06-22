//#include <stdio.h>
#include <stdlib.h>

extern void bpf_map_write_active(void) { abort(); }
extern int pagefault_disable() { return 1; }

void * kmalloc (size_t size) { }

int main() {
  //printf("Starting runtime...");

  //printf("foo returns: %d", foo());

  return 0;
}
