#include <setjmp.h>

// TODO: split testing functions out to a separate file.
extern int bpf_prog_load(union bpf_attr *, bpfptr_t);

void test(union bpf_attr *a, bpfptr_t *b, char * descr ) {
	int res = setjmp(env_buffer);
	if (res != 0) {
		switch (res) {
			case 1:
				printf("Test \"%s\": REJECTED\n", descr);
				break;
			case 2:
				printf("Test \"%s\": ACCEPTED\n", descr);
				break;
			default:
				printf("Unrecognized return value %d.\n", res);
		}
	} else {
		bpf_prog_load(a, *b);
	}
}
