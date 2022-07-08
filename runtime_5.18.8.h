//inline assembly
/* Optimization barrier */
#ifndef barrier
/* The "volatile" is due to gcc bugs */
# define barrier() __asm__ __volatile__("": : :"memory")
#endif


# define unlikely(x)	__builtin_expect(!!(x), 0)
