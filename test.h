#ifndef _TEST_H
#define _TEST_H
#include <linux/bpf.h> // make sure this links to the correct one when compiling
#include <stdbool.h>
#include <setjmp.h>

typedef struct {
	union {
		void	*kernel;
		void 	*user;
	};
	bool		is_kernel : true;
} sockptr_t;

typedef sockptr_t bpfptr_t;
static jmp_buf env_buffer;

void test(union bpf_attr *, bpfptr_t *, char *);

#endif // _TEST_H
