#include <linux/preempt.h>

#undef in_nmi
#define in_nmi() false

#ifdef __v5_2__
#undef preempt_enable
#define preempt_enable()

#undef preempt_disable
#define preempt_disable()
#endif
