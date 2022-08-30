extern unsigned long copy_from_user(void * to, const void * from, unsigned long n);
extern unsigned long copy_to_user(void * to, const void * from, unsigned long n);
extern long strncpy_from_user(char *dest, const char *src, long count);

#ifdef __v5_18__
#define __LINUX_UACCESS_H__

extern unsigned long strlen(const char *str);

inline static long strncpy_from_user(char *dest, const char *src, long count) {
  __builtin_strncpy(dest, src, count);
  // return min of strlen(src) and count
  if (strlen(src) < count) {
    return strlen(src);
  }
  return count;
}

// TODO: don't really get this one
inline static long put_user(unsigned long x, void *ptr) {return 0;}

extern int pagefault_disable(void);
extern int pagefault_enable(void);

#else
#define __ASM_UACCESS_H

#undef access_ok
#define access_ok(type, addr, size)	true

extern unsigned long  __copy_to_user(void  *to, const void *from, unsigned long n);

#define get_user(x, ptr) x = *ptr

#endif

