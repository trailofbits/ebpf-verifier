// first part covering stuff found in arch/arm64/include/asm/uaccess.h
// second part covering stuff found in include/linux/uaccess.h

#ifndef __ASM_UACCESS_H
#define __ASM_UACCESS_H

extern unsigned long strlen(const char *str);

inline static unsigned long raw_copy_from_user(void * to, const void * from, unsigned long n) {
  __builtin_memcpy(to, from, n);
  return n;
}

inline static unsigned long raw_copy_to_user(void * to, const void * from, unsigned long n) {
  __builtin_memcpy(to, from, n);
  return n;
}

inline static long strncpy_from_user(char *dest, const char *src, long count) {
  __builtin_strncpy(dest, src, count);
  // return min of strlen(src) and count
  if (strlen(src) < count) {
    return strlen(src);
  }
  return count;
}

#define strncpy_from_user_nofault strncpy_from_user
#define strncpy_from_kernel_nofault strncpy_from_user

#define copy_from_kernel_nofault copy_from_user

// TODO: don't really get this one
inline static long put_user(unsigned long x, void *ptr) {return 0;}
#endif

#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

extern int pagefault_disable(void);
extern int pagefault_enable(void);

#define _copy_to_user raw_copy_to_user
#define _copy_from_user raw_copy_from_user
#define copy_to_user raw_copy_to_user
#define copy_from_user raw_copy_from_user

#endif
