#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <linux/bpf.h> // make sure this links to the correct one when compiling
#include <linux/filter.h>

extern size_t strlcpy(char *, const char *, size_t);

#define MAX_INSNS	BPF_MAXINSNS

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

struct bpf_test {
	const char *descr;
	struct bpf_insn insns[MAX_INSNS];
	struct bpf_insn *fill_insns;
	int prog_len;
	enum bpf_prog_type prog_type;
};

typedef struct {
	union {
		void	*kernel;
		void 	*user;
	};
	bool		is_kernel : true;
} sockptr_t;

typedef sockptr_t bpfptr_t;


extern int bpf_prog_load(union bpf_attr *, bpfptr_t);

int main() {

	struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_0, 5),
		BPF_EXIT_INSN(),
	};

	// selftest calls libbpf:
	// return bpf_prog_load(prog_type, NULL, "GPL", prog, ARRAY_SIZE(prog), NULL);
	// LIBBPF_API int bpf_prog_load(enum bpf_prog_type prog_type,
			    //  const char *prog_name, const char *license,
			    //  const struct bpf_insn *insns, size_t insn_cnt,
			    //  const struct bpf_prog_load_opts *opts);

	enum bpf_prog_type prog_type = BPF_PROG_TYPE_XDP;
	char *prog_name = "test";
	char *license = "GPL";
	struct bpf_insn *insns = prog;
	size_t insn_cnt = ARRAY_SIZE(prog);
	struct bpf_prog_load_opts *opts = NULL;


  union bpf_attr * a = (union bpf_attr *) calloc(1, sizeof(union bpf_attr));

	a->prog_type = prog_type;
	strlcpy(a->prog_name, prog_name, sizeof(a->prog_name));
	a->license = (__u64) (unsigned long) license;
	a->insns = (__u64) (unsigned long) insns;
	a->insn_cnt = (__u32) insn_cnt;




	// what is uattr supposed to point to for bpf_prog_load?
  bpfptr_t * b = (bpfptr_t *) malloc(sizeof(bpfptr_t));
	b->is_kernel = true;
	b->kernel = NULL;
	b->user = NULL;

  bpf_prog_load(a, *b);

  return 0;
}
