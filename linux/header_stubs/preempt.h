#include <linux/preempt.h>

#undef in_nmi
#define in_nmi() false
