#include <linux/mm_types.h>

// unsigned long page_size(void) { return PAGE_SIZE; }
size_t sizeof_page_struct(void) { return sizeof(struct page); }
