#include <stddef.h>
#include <stdlib.h>
#include "ptr_store.h"

static struct ptr_store *store;

void init_ptr_store() {
	store = new_ptr_store();
}

void destroy_ptr_store() {
	free_store(store);
}

void * kcalloc(size_t n, size_t size) { return add_ptr(store, calloc(n, size)); }
void kfree(void *ptr) {}
void *kmalloc(size) { return add_ptr(store, calloc(1, size)); }
// extern decl from include/linux/vmalloc.h
void * vmalloc(unsigned long size) { return add_ptr(store, calloc(1, size)); }
void * vzalloc(size_t size) {	return add_ptr(store, calloc(1, size)); }
void kvfree(void *ptr) {}
void vfree(void *ptr) {}
void *kmalloc_array(size_t n, size_t size, unsigned int flags) { return add_ptr(store, calloc(1, n *size)); }

struct callback_head;
void kfree_call_rcu(struct callback_head *head, void (*func)(struct callback_head *)) {}

void * kzalloc(size_t size) { return add_ptr(store, calloc(1, size)); }
void * __vmalloc(unsigned long size) { return add_ptr(store, calloc(1, size)); }

#if defined __v5_18__ || __v5_2__
void * kvcalloc(size_t n, size_t size) { return add_ptr(store, calloc(n, size)); }
void * kvmalloc(size_t n, unsigned int flags) { return add_ptr(store, calloc(1, n)); }

void * kmalloc_node(size_t size, unsigned int flags, int node) { return add_ptr(store, calloc(1, size)); }
void * __kmalloc_track_caller(size_t size, unsigned int flags, unsigned long caller) { return add_ptr(store, calloc(1, size)); }
void kmalloc_array_node(void) { abort(); } // TODO --> autogened

void free_percpu(void * ptr) {}

void * krealloc(void *p, size_t new_size, unsigned int flags) { return add_ptr(store, malloc(new_size)); }
void * krealloc_array(void *p, size_t new_n, size_t new_size, unsigned int flags) { return add_ptr(store, calloc(new_n, new_size)); }

void * __vmalloc_node_range(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, unsigned int gfp_mask,
			unsigned int prot, unsigned long vm_flags, int node,
			const void *caller) { return add_ptr(store, calloc(1, size)); }

void * __alloc_percpu_gfp(size_t size, size_t align) { return add_ptr(store, calloc(1, size)); }
void * __alloc_percpu(size_t size, size_t align) { return add_ptr(store, calloc(1, size)); } // TODO --> autogened

void kmem_cache_alloc_lru(void) { abort(); } // TODO --> autogened
void* kmem_cache_create_usercopy(void) { return NULL; } // TODO --> autogened
void kmem_cache_free(void) { abort(); } // TODO --> autogened
void* kmem_cache_create(void) { return NULL; }

void * alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit) { return add_ptr(store, malloc(10*bucketsize)); } // TODO --> autogened

struct page;
extern size_t sizeof_page_struct();
struct page *__alloc_pages(unsigned int gfp, unsigned int order, int preferred_nid,
							void *nodemask) { return (struct page *)add_ptr(store, calloc(1, sizeof_page_struct())); }
void *vmap(struct page **pages, unsigned int count,  unsigned long flags, unsigned long prot) {
	// this isn't actually mapping anything
	return add_ptr(store, calloc(count, sizeof_page_struct()));
}


void alloc_pages(void) { abort(); } // TODO --> autogened
void kmem_cache_alloc_bulk(void) { abort(); } // TODO --> autogened
void kmemdup(void) { abort(); } // TODO --> autogened
void kmemdup_nul(void) { abort(); } // TODO --> autogened
void kvfree_call_rcu(void) { abort(); } // TODO --> autogened
void kvmalloc_array(void) { abort(); } // TODO --> autogened

#endif
