extern unsigned long copy_from_user(void * to, const void * from, unsigned long n);
extern unsigned long copy_to_user(void * to, const void * from, unsigned long n);
extern long strncpy_from_user(char *dest, const char *src, long count);
extern int check_zeroed_user(const void  *from, unsigned int size);

#if defined __v5_18__ || defined __v5_2__
#define __LINUX_UACCESS_H__

extern unsigned long strlen(const char *str);
extern long copy_from_kernel_nofault(void *dst, const void *src, size_t size);
// TODO: don't really get this one
inline static long put_user(unsigned long x, void *ptr) {return 0;}

extern int pagefault_disable(void);
extern int pagefault_enable(void);

#endif

#ifdef __v5_2__
#define __ASM_UACCESS_H

#undef access_ok
#define access_ok(addr, size)	true
#define get_fs()	(current_thread_info()->addr_limit)

// #define segment_eq(a, b) ((a).seg == (b).seg)
#define segment_eq(a, b) (a == b) // TODO? what is this?

#define get_user(x, ptr) x = *ptr

#endif

#ifdef __v4_0

#define __ASM_UACCESS_H

#undef access_ok
#define access_ok(type, addr, size)	true

extern unsigned long  __copy_to_user(void  *to, const void *from, unsigned long n);

#define get_user(x, ptr) x = *ptr

#endif

