#include <linux/bpf.h> // make sure this links to the correct one when compiling


typedef struct {
	union {
		void	*kernel;
		void 	*user;
	};
	bool		is_kernel : true;
} sockptr_t;

typedef sockptr_t bpfptr_t;


void test(union bpf_attr *, bpfptr_t *);
