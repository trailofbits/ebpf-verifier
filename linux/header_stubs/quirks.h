#ifdef __v5_2__
#include <linux/compiler.h>

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...)
#endif

#endif


