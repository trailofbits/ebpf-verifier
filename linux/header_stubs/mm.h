#ifdef __v5_2__
#define _LINUX_MM_H

struct page;
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))

extern void *page_address(const struct page *page);
extern bool page_is_pfmemalloc(struct page *page);
extern void get_page(struct page *page);
extern void put_page(struct page *page);
extern int in_gate_area_no_mm(unsigned long addr);
extern bool is_vmalloc_addr(const void *x);
extern void *kvcalloc(size_t n, size_t size, gfp_t flags);
extern void *kvmalloc(size_t size, gfp_t flags);

#endif
