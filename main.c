#include "other.h"

extern int bpf_check(void * a, union bpf_attr *b, void * c);

int main() {

  // trying to model/simplify the flow that the bpf program goes through
  // based on a test in tools/testing/selftests/bpf/progs/syscall.c
  // idea: have a bpf program
  // somehow convert it into the attribute object and program object
  // that the verifier (bpf_check()) needs.
  // the test flow goes something like:
  // 1. in test: specify exact instructions, license, other attributes
  // 2. Call bpf_sys_bpf(BPF_PROG_LOAD, &prog_load_attr, sizeof(prog_load_attr))
  // this goes to line 4782 in kernel/bpf/syscall.c



  static char license[] = "GPL";
  static struct bpf_insn insns[] = {
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

  static union bpf_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insn_cnt = sizeof(insns) / sizeof(insns[0]),
	};

  prog_load_attr.license = (long) license;
	prog_load_attr.insns = (long) insns;

  // convert prog_load_attr to bpfptr_t???
  // size = sizeof(prog_load_attr)
  union bpf_attr attr;
  // it does some checks ....
  // makes sure size is actually correct? --> takes the min
  // copies attributes from user space --> can probably skip
  // calls security_bpf() --> no idea what this really is for
  // calls bpf_prog_load(&attr, uattr) --> not sure why both attr things are necessary?



  // 3. BPF_CALL_3(bpf_sys_bpf) ---> __sys_bpf(cmd, KERNEL_BPFPTR(attr), attr_size)
  // 4. creates union bpf_attr (copies stuff from that bpfptr uattr)
  // 5. checks size/updates
  // 6. security_bpf()?
  // 7. calls bpf_prog_load(&attr, uattr);
  // 8. somehow creates the bpf_prog object and then finally calls the verifier

  struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  prog->pages = 5;

  union bpf_attr at = { 7 };
  bpf_check(&prog, &at, NULL);
  return 0;
}
