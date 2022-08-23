#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

struct ptr_store {
  size_t capacity;
  size_t index;
  void ** ptrs;
};

#define INIT_SIZE 100

struct ptr_store * new_ptr_store() {
  void * p = malloc(INIT_SIZE * sizeof(void *));
  struct ptr_store *store = malloc(sizeof(struct ptr_store));
  store->capacity = INIT_SIZE;
  store->index = 0;
  store->ptrs = p;
  return store;
}

bool full(struct ptr_store *store) {
  return store->index == store->capacity;
}

void expand(struct ptr_store *store) {
  void *p = malloc(store->capacity * 2 * sizeof(void *)); // double capacity
  memcpy(p, store->ptrs, store->capacity * sizeof(void *));
  free(store->ptrs);
  store->ptrs = p;
  store->capacity = store->capacity * 2;
}


struct ptr_store * add_ptr(struct ptr_store *store, void *p) {
  if (full(store)) {
    expand(store);
  }
  store->ptrs[store->index] = p;
  store->index++;
  return p;
}

void free_store(struct ptr_store *store) {
  for (size_t i = 0; i < store->index; i++) {
    free(store->ptrs[i]);
  }
  free(store->ptrs);
  free(store);
}
