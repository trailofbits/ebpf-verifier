#include <linux/refcount.h>

inline void refcount_inc_checked(refcount_t *r) { atomic_inc(&r->refs); } // TODO --> autogened
inline bool refcount_inc_not_zero_checked(refcount_t *r) { atomic_inc(&r->refs); return true; } // TODO --> autogened
