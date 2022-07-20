#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hello.skel.h"

extern size_t strlcpy(char *, const char *, size_t);

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

struct bpf_program {
	struct bpf_insn *insns;
	enum bpf_prog_type type;
	char *name;
	size_t insns_cnt;
};

int main(void)
{
	struct hello_bpf *obj;
	int err = 0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}


	obj = hello_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	fprintf(stdout, "opened file. Calling verifier through harness.\n");

	struct bpf_program *bp = *obj->skeleton->progs->prog;
	struct bpf_insn *insns = bp->insns;
	char *license = "GPL";
	union bpf_attr * a = (union bpf_attr *) calloc(1, sizeof(union bpf_attr));

	a->prog_type = bp->type;
	//strlcpy(a->prog_name, bp->name, sizeof(a->prog_name));
	memcpy(a->prog_name, bp->name, sizeof(a->prog_name));
	a->license = (__u64) (unsigned long) license;
	a->insns = insns;
	a->insn_cnt = bp->insns_cnt;

	// what is uattr supposed to point to for bpf_prog_load?
  bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t));
	b->is_kernel = true;
	b->kernel = NULL;
	b->user = NULL;

	test(a, b, "hot test");

	goto cleanup;

	// err = hello_bpf__load(obj);
	// if (err) {
	// 	fprintf(stderr, "failed to load BPF object %d\n", err);
	// 	goto cleanup;
	// }

	// err = hello_bpf__attach(obj);
	// if (err) {
	// 	fprintf(stderr, "failed to attach BPF programs\n");
	// 	goto cleanup;
	// }

	// read_trace_pipe();

cleanup:
	hello_bpf__destroy(obj);
	return err != 0;
}
