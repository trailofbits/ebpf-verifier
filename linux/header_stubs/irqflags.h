#include <linux/irqflags.h>

#undef local_irq_save
#define local_irq_save(flags) flags = 0

#undef local_irq_restore
#define local_irq_restore(flags) flags = 0
