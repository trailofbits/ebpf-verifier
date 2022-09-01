#include <linux/bpf.h>

extern int sys_bpf(int, union bpf_attr *, int);

int main() {

	return _do_sys_bpf(4, (void *)0, 5);
}
