#include <setjmp.h>

// TODO: split testing functions out to a separate file.
extern int bpf_prog_load(union bpf_attr *, bpfptr_t);
extern void __bpf_prog_free(struct bpf_prog *);

static jmp_buf env_buffer;

int test(union bpf_attr *a, bpfptr_t *b, char * descr ) {
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
		return bpf_prog_load(a, *b);
	}
	return 7; // TODO: return and end behavior of test is going to need to be redone.
}

// first functions called in verifier.c (within bpf_check) after completing verification
// add to core.bc compile command: -Dbpf_prog_select_runtime=bpf_prog_select_runtime_orig -Dbpf_prog_kallsyms_del_all=bpf_prog_kallsyms_del_all_orig
void bpf_prog_kallsyms_del_all(struct bpf_prog *fp) {
	__bpf_prog_free(fp);
	longjmp(env_buffer, 1); // REJECTED
}
void bpf_prog_select_runtime(struct bpf_prog *fp, int *err) {
	__bpf_prog_free(fp);
	longjmp(env_buffer, 2); // ACCEPTED
}

