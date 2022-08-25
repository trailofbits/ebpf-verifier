#define _LINUX_ATOMIC_INSTRUMENTED_H
#include <linux/types.h>
#ifdef  __v5_18__
extern void abort(void);

typedef atomic64_t atomic_long_t;




extern bool atomic_add_unless(atomic_t *v, int a, int u);
extern bool atomic_dec_and_test(atomic_t *v);
extern bool atomic_dec_unless_positive(atomic_t *v);
extern bool atomic_inc_not_zero(atomic_t *v);
extern bool atomic_inc_unless_negative(atomic_t *v);
extern bool atomic_long_add_unless(atomic_long_t *v, long a, long u);
extern bool atomic_long_inc_not_zero(atomic_long_t *v);
extern bool atomic_long_sub_and_test(long i, atomic_long_t *v);
extern bool atomic_sub_and_test(int i, atomic_t *v);
extern bool atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new);
extern bool atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new);
extern bool atomic64_dec_and_test(atomic64_t *v);
extern int atomic_add_return_acquire(int i, atomic_t *v);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_dec_return(atomic_t *v);
extern int atomic_fetch_add_relaxed(int i, atomic_t *v);
extern int atomic_fetch_add_release(int i, atomic_t *v);
extern int atomic_fetch_add(int i, atomic_t *v);
extern int atomic_fetch_sub_release(int i, atomic_t *v);
extern int atomic_inc_return(atomic_t *v);
extern int atomic_read(const atomic_t *v);
extern int atomic_sub_return_release(int i, atomic_t *v);
extern int atomic_sub_return(int i, atomic_t *v);
extern long atomic_long_add_return(long i, atomic_long_t *v);
extern long atomic_long_dec_return(atomic_long_t *v);
extern long atomic_long_inc_return_relaxed(atomic_long_t *v);
extern long atomic_long_inc_return(atomic_long_t *v);
extern long atomic_long_read(const atomic_long_t *v);
extern long atomic_long_sub_return(long i, atomic_long_t *v);
extern s64 atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new);
extern s64 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u);
extern s64 atomic64_read(const atomic64_t *v);
extern s64 atomic64_sub_return(s64 i, atomic64_t *v);
extern void atomic_add(int i, atomic_t *v);
extern void atomic_dec(atomic_t *v);
extern void atomic_inc(atomic_t *v);
extern void atomic_long_add(long i, atomic_long_t *v);
extern void atomic_long_dec(atomic_long_t *v);
extern void atomic_long_inc(atomic_long_t *v);
extern void atomic_long_set_release(atomic_long_t *v, long i);
extern void atomic_long_set(atomic_long_t *v, long i);
extern void atomic_long_sub(long i, atomic_long_t *v);
extern void atomic_set_release(atomic_t *v, int i);
extern void atomic_set(atomic_t *v, int i);
extern void atomic_sub(int i, atomic_t *v);
extern void atomic64_add(s64 i, atomic64_t *v);
extern void atomic64_dec(atomic64_t *v);
extern void atomic64_inc(atomic64_t *v);
extern void atomic64_set(atomic64_t *v, s64 i);

#define xchg(ptr, ...) *ptr // TODO --> actually replicate functionality?
#define xchg_relaxed(ptr, ...) *ptr // TODO --> actually replicate functionality?

#define cmpxchg(ptr, ...) true // TODO --> actually replicate functionality?
#define cmpxchg_relaxed(ptr, ...) true // TODO --> actually replicate functionality?

#define try_cmpxchg_acquire(ptr, ...) true // TODO --> actually replicate functionality?
#define try_cmpxchg_release(ptr, ...) true // TODO --> actually replicate functionality?
#endif /* __v5_18__ */
