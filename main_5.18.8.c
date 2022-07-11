#include <stdlib.h>
#include <stdbool.h>


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
  union bpf_attr * a = (union bpf_attr *) malloc(sizeof(union bpf_attr));
  bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t));

  bpf_prog_load(a, *b);

  return 0;
}
