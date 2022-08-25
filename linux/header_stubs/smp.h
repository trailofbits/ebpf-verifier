#include <asm/smp.h>

#undef raw_smp_processor_id
#define raw_smp_processor_id() 0
