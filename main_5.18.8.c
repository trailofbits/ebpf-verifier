// /* simple_main.c --> calls bpf_check directly with invalid args. */

// #include <stddef.h>
// #include <stdint.h>
// #include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


// #include <unistd.h>

//#include <linux/bpf.h>
//#include <linux/syscalls.h>

//extern int __sys_bpf(int, void *, int);
//extern int bpf_sys_bpf(int, int, void *, void *, int, int);
//extern long bpf_sys_bpf(u32 cmd, void *attr, u32 attr_size);


//char bpf_log_buf[1024];

// enum bpf_cmd {
// 	BPF_MAP_CREATE,
// 	BPF_MAP_LOOKUP_ELEM,
// 	BPF_MAP_UPDATE_ELEM,
// 	BPF_MAP_DELETE_ELEM,
// 	BPF_MAP_GET_NEXT_KEY,
// 	BPF_PROG_LOAD,
// };

//#define BPF_PROG_LOAD

// static int test(void)
// {
//   // int sock = -1, map_fd, prog_fd, i, key;

//   // struct bpf_insn prog[] = {BPF_EXIT_INSN(),};
//   // size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);
//   // struct bpf_prog_load_opts opts = {};

//   //int prog_fd = __sys_bpf(2, (void *)0, 0);
//   //int prog_fd = bpf_sys_bpf(1, 1, (void *)0, (void *)0, 5, 2);
//   //int prog_fd = bpf_prog_load((void *)0, (void *)0);
//   //printf("FD: %d", prog_fd);
//   //close(prog_fd);
//   //return prog_fd;
//   return 1;
//   // prog_fd = bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, "GPL", prog, insns_cnt, &opts);
// }

union bpf_attr {
  struct { /* anonymous struct used by BPF_PROG_LOAD command */
    unsigned long prog_type;
		//__u32		prog_type;	/* one of enum bpf_prog_type */
		// __u32		insn_cnt;
		// __aligned_u64	insns;
		// __aligned_u64	license;
		// __u32		log_level;	/* verbosity level of verifier */
		// __u32		log_size;	/* size of user buffer */
		// __aligned_u64	log_buf;	/* user supplied buffer */
		// __u32		kern_version;	/* checked when prog_type=kprobe */
		// __u32		prog_flags;
		// char		prog_name[BPF_OBJ_NAME_LEN];
		// __u32		prog_ifindex;	/* ifindex of netdev to prep for */
		// /* For some prog types expected attach type must be known at
		//  * load time to verify attach type specific parts of prog
		//  * (context accesses, allowed helpers, etc).
		//  */
		// __u32		expected_attach_type;
	};
};

typedef struct {
	union {
		void		*kernel;
		void 	*user;
	};
	bool		is_kernel : 1;
} sockptr_t;

typedef sockptr_t bpfptr_t;

extern int bpf_prog_load(union bpf_attr *, bpfptr_t);

int main() {
  //test();
  union bpf_attr * a = (union bpf_attr *) malloc(sizeof(union bpf_attr));
  bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t));
  bpf_prog_load(a, *b);
  return 0;
}
