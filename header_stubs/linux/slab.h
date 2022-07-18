// stubbed version of include/linux/slab.h
#define	_LINUX_SLAB_H
#include<linux/types.h>

#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
extern void kfree_sensitive(const void *objp);

#ifdef CONFIG_SLAB

/*
 * The largest kmalloc size supported by the SLAB allocators is
 * 32 megabyte (2^25) or the maximum allocatable page order if that is
 * less than 32 MB.
 *
 * WARNING: Its not easy to increase this value since the allocators have
 * to do various tricks to work around compiler limitations in order to
 * ensure proper constant folding.
 */
#define KMALLOC_SHIFT_HIGH	((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? \
				(MAX_ORDER + PAGE_SHIFT - 1) : 25)
#define KMALLOC_SHIFT_MAX	KMALLOC_SHIFT_HIGH
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	5
#endif
#endif

#ifdef CONFIG_SLUB
/*
 * SLUB directly allocates requests fitting in to an order-1 page
 * (PAGE_SIZE*2).  Larger requests are passed to the page allocator.
 */
#define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
#define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT - 1)
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	3
#endif
#endif

#ifdef CONFIG_SLOB
/*
 * SLOB passes all requests larger than one page to the page allocator.
 * No kmalloc array is necessary since objects of different sizes can
 * be allocated from the same page.
 */
#define KMALLOC_SHIFT_HIGH	PAGE_SHIFT
#define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT - 1)
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	3
#endif
#endif

/* Maximum allocatable size */
#define KMALLOC_MAX_SIZE	(1UL << KMALLOC_SHIFT_MAX)
/* Maximum size for which we actually use a slab cache */
#define KMALLOC_MAX_CACHE_SIZE	(1UL << KMALLOC_SHIFT_HIGH)
/* Maximum order allocatable via the slab allocator */
#define KMALLOC_MAX_ORDER	(KMALLOC_SHIFT_MAX - PAGE_SHIFT)

/*
 * Kmalloc subsystem.
 */
#ifndef KMALLOC_MIN_SIZE
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#endif

/*
 * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
 *
 * Dereferencing ZERO_SIZE_PTR will lead to a distinct access fault.
 *
 * ZERO_SIZE_PTR can be passed to kfree though in the same way that NULL can.
 * Both make kfree a no-op.
 */
#define ZERO_SIZE_PTR ((void *)16)

#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)

struct kmem_cache {};
struct list_lru;

extern void * kzalloc(size_t size, gfp_t flags);
extern void kfree(const void *objp);
extern void kvfree(const void *objp);
extern void * kmalloc(size_t size, gfp_t flags);
extern void * kmem_cache_alloc(struct kmem_cache *s, gfp_t flags);
extern void kmem_cache_free(struct kmem_cache *s, void *objp);
extern void * kcalloc(int num, size_t size, gfp_t flags);
extern void * kvmalloc(size_t size, gfp_t flags);
extern void * kvcalloc(size_t n, size_t size, gfp_t flags);
extern void *  krealloc(const void *objp, size_t new_size, gfp_t flags);
extern void * kmalloc_array(size_t n, size_t size, gfp_t flags);
extern void *kvmalloc_array(size_t n, size_t size, gfp_t flags);
extern void *__kmalloc_track_caller(size_t size, gfp_t flags, unsigned long caller);
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)

extern void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
			   gfp_t gfpflags);
extern void *  krealloc_array(void *p, size_t new_n, size_t new_size, gfp_t flags);
extern void *kmalloc_node(size_t size, gfp_t flags, int node);
extern size_t ksize(const void *objp);
