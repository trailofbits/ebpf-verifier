#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "main.skel.h"

int main(void)
{
	struct main_bpf *obj;
	int err = 0;

	obj = main_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = main_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

cleanup:
	main_bpf__destroy(obj);
	return err != 0;
}
