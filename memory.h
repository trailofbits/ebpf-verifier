#include <stdbool.h>

struct ptr_store;

struct ptr_store * new_ptr_store(void);
bool full(struct ptr_store *store);
void expand(struct ptr_store *store);
void add_ptr(struct ptr_store *store, void *p);
void free_store(struct ptr_store *store);
