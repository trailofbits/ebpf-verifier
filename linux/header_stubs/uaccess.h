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


inline unsigned long copy_from_user(void * to, const void * from, unsigned long n) {
  __builtin_memcpy(to, from, n);
  return n;
}

inline unsigned long copy_to_user(void * to, const void * from, unsigned long n) {
  if (to && from) {
    __builtin_memcpy(to, from, n);
    return 0;
  } else {
    return n;
  }
}


// copy_from_kernel_nofault
// strncpy_from_user_nofault
// check_zeroed_user
// __uaccess_enable_tco_async
// __uaccess_disable_tco_async
// __uaccess_enable_tco_async
// get_kernel_nofault
