#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdbool.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "s.skel.h"

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}


int main(void)
{
	struct s_bpf *obj;
	int err = 0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};
	libbpf_set_print(libbpf_print_fn);

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	char *path = "/home/parallels/ebpf-verifier/linux/vmlinux.h";

	struct bpf_object_open_opts opts = {
		.sz = 0,
		.btf_custom_path = path,
	};

	opts.sz = sizeof(opts);

	obj = s_bpf__open_opts(&opts);
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	//bpf_map__set_autocreate(obj->maps.rodata, false);

	err = s_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = s_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	read_trace_pipe();

cleanup:
	s_bpf__destroy(obj);
	return err != 0;
}
