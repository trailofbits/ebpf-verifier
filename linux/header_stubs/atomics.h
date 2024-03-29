// TODO: this file needs life support. super ugly.
#include <linux/types.h>
typedef atomic64_t atomic_long_t;

#ifdef __v5_2__

#define _ASM_GENERIC_ATOMIC_LONG_H
#define _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
#define _LINUX_ATOMIC_FALLBACK_H

extern void atomic_long_or(long i, atomic_long_t *v);
extern void atomic_long_andnot(long i, atomic_long_t *v);
extern void atomic_long_xor(long i, atomic_long_t *v);
extern long atomic_long_fetch_or(long i, atomic_long_t *v);
extern long atomic_long_fetch_andnot(long i, atomic_long_t *v);
extern long atomic_long_fetch_xor(long i, atomic_long_t *v);
extern long atomic_long_fetch_or_acquire(long i, atomic_long_t *v);
extern long atomic_long_fetch_andnot_release(long i, atomic_long_t *v);

extern int atomic_add_return(int i, atomic_t *v);
extern int atomic_fetch_add_unless(atomic_t *v, int a, int u);

static inline long atomic_long_add_return(long i, atomic_long_t *v) {return 0; }
static inline void atomic_long_sub(long i, atomic_long_t *v) { (v)->counter -= i; }
static inline void atomic_long_add(long i, atomic_long_t *v) { (v)->counter += i; }
static inline void atomic_long_set(atomic_long_t *v, long i) {(v)->counter = i; }
static inline void atomic_long_dec(atomic_long_t *v) { (v)->counter -= 1; }
static inline void atomic_long_inc(atomic_long_t *v) { (v)->counter += 1; }
static inline void atomic_long_set_release(atomic_long_t *v, long i) { (v)->counter = i;}
static inline void atomic_add(int i, atomic_t *v) {(v)->counter += i; }
#define atomic_read(v)  (v)->counter
#define atomic_long_read(v) (v)->counter
static inline void atomic_sub(long i, atomic_t *v) { (v)->counter -= i; }
static inline void atomic_inc(atomic_t *v) {(v)->counter += 1; }
static inline void atomic_dec(atomic_t *v) {(v)->counter -= 1; }
static inline int atomic_add_return_acquire(int i, atomic_t *v) { (v)->counter += i; return (v)->counter;}
static inline int atomic_inc_return(atomic_t *v) {(v)->counter += 1; return (v)->counter;}

#define xchg(ptr, ...) *ptr // TODO --> actually replicate functionality?
#define xchg_relaxed(ptr, ...) *ptr // TODO --> actually replicate functionality?

#define cmpxchg(ptr, ...) true // TODO --> actually replicate functionality?
#define cmpxchg_relaxed(ptr, ...) true // TODO --> actually replicate functionality?

#define atomic_set(v, i) (v)->counter = i

extern bool atomic_inc_unless_negative(atomic_t *v);
extern bool atomic_dec_unless_positive(atomic_t *v);
extern bool atomic_dec_and_test(atomic_t *v);
extern bool atomic_sub_and_test(int i, atomic_t *v);
extern bool atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new);
extern int atomic_sub_return(int i, atomic_t *v);
extern void atomic_set_release(atomic_t *v, int i);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_dec_return(atomic_t *v);

extern bool atomic_long_sub_and_test(long i, atomic_long_t *v);
extern bool atomic_long_inc_not_zero(atomic_long_t *v);
extern bool atomic_add_unless(atomic_t *v, int a, int u);
extern int atomic_sub_return_release(int i, atomic_t *v);
extern bool atomic_inc_not_zero(atomic_t *v);

#elif defined(__v5_18__)

#define _LINUX_ATOMIC_INSTRUMENTED_H
extern bool atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new);
extern int atomic_sub_return_release(int i, atomic_t *v);
extern long atomic_long_inc_return_relaxed(atomic_long_t *v);
extern bool atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new);
static inline int atomic_fetch_add_relaxed(int i, atomic_t *v) {
  int old = (v)->counter;
  (v)->counter += i;
  return old;
}
static inline int atomic_fetch_sub_release(int i, atomic_t *v) {
  int old  = (v)->counter;
  (v)->counter -= i;
  return old;
}
extern bool atomic_inc_unless_negative(atomic_t *v);
extern long atomic_long_sub_return(long i, atomic_long_t *v);

extern bool atomic_inc_unless_negative(atomic_t *v);
extern bool atomic_dec_unless_positive(atomic_t *v);
extern bool atomic_dec_and_test(atomic_t *v);
extern bool atomic_sub_and_test(int i, atomic_t *v);
extern bool atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new);
extern int atomic_sub_return(int i, atomic_t *v);
extern void atomic_set_release(atomic_t *v, int i);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_dec_return(atomic_t *v);

extern bool atomic_long_sub_and_test(long i, atomic_long_t *v);
extern bool atomic_long_inc_not_zero(atomic_long_t *v);
extern bool atomic_add_unless(atomic_t *v, int a, int u);
extern int atomic_sub_return_release(int i, atomic_t *v);
extern bool atomic_inc_not_zero(atomic_t *v);
extern bool atomic_long_add_unless(atomic_long_t *v, long a, long u);
extern long atomic_long_inc_return(atomic_long_t *v);
extern long atomic_long_dec_return(atomic_long_t *v);
extern void atomic64_dec(atomic64_t *v);
extern bool atomic64_dec_and_test(atomic64_t *v);

static inline long atomic_long_add_return(long i, atomic_long_t *v) {return 0; }
static inline void atomic_long_sub(long i, atomic_long_t *v) { (v)->counter -= i; }
static inline void atomic_long_add(long i, atomic_long_t *v) { (v)->counter += i; }
static inline void atomic_long_set(atomic_long_t *v, long i) {(v)->counter = i; }
static inline void atomic_long_dec(atomic_long_t *v) { (v)->counter -= 1; }
static inline void atomic_long_inc(atomic_long_t *v) { (v)->counter += 1; }
static inline void atomic_long_set_release(atomic_long_t *v, long i) { (v)->counter = i;}
static inline void atomic_add(int i, atomic_t *v) {(v)->counter += i; }
#define atomic_read(v)  (v)->counter
#define atomic_long_read(v) (v)->counter
static inline void atomic_sub(long i, atomic_t *v) { (v)->counter -= i; }
static inline void atomic_inc(atomic_t *v) {(v)->counter += 1; }
static inline void atomic_dec(atomic_t *v) {(v)->counter -= 1; }
static inline int atomic_add_return_acquire(int i, atomic_t *v) { (v)->counter += i; return (v)->counter;}
static inline int atomic_inc_return(atomic_t *v) {(v)->counter += 1; return (v)->counter;}
extern s64 atomic64_read(const atomic64_t *v);
extern void atomic64_inc(atomic64_t *v);
extern s64 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u);

#define xchg(ptr, ...) *ptr // TODO --> actually replicate functionality?
#define xchg_relaxed(ptr, ...) *ptr // TODO --> actually replicate functionality?

#define cmpxchg(ptr, ...) true // TODO --> actually replicate functionality?
#define cmpxchg_relaxed(ptr, ...) true // TODO --> actually replicate functionality?

#define atomic_set(v, i) (v)->counter = i

#define xchg(ptr, ...) *ptr // TODO --> actually replicate functionality?
#define xchg_relaxed(ptr, ...) *ptr // TODO --> actually replicate functionality?

#define cmpxchg(ptr, ...) true // TODO --> actually replicate functionality?
#define cmpxchg_relaxed(ptr, ...) true // TODO --> actually replicate functionality?

extern int atomic_fetch_add_release(int i, atomic_t *v);
extern int atomic_fetch_add(int i, atomic_t *v);
extern s64 atomic64_sub_return(s64 i, atomic64_t *v);
extern void atomic64_add(s64 i, atomic64_t *v);
extern void atomic64_set(atomic64_t *v, s64 i);


#define try_cmpxchg_acquire(ptr, ...) true // TODO --> actually replicate functionality?
#define try_cmpxchg_release(ptr, ...) true // TODO --> actually replicate functionality?

#endif
