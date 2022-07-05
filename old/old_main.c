//#include "other.h"

//need to include the appropriate linux header files (just user header files!)
// #include "linux-5.18.4/include/uapi/linux/stddef.h"
// #include "linux-5.18.4/include/uapi/linux/bpf.h"
// #include "linux-5.18.4/tools/lib/bpf/bpf_helpers.h"
// #include "linux-5.18.4/tools/lib/bpf/bpf_tracing.h"
// #include "linux-5.18.4/tools/include/linux/filter.h"
// #include "linux-5.18.4/include/uapi/linux/bpf.h"
//#include <linux/stddef.h>
//#include </home/parallels/ebpf-verifier/linux-5.18.4/include/uapi/linux/stddef.h>

#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/stddef.h>
#include </home/parallels/ebpf-verifier/linux-5.18.4/tools/include/linux/filter.h>
#include <linux/btf.h>
#include <linux/types.h>
// #include <linux/filter.h>
#include </home/parallels/ebpf-verifier/linux-5.18.4/tools/lib/bpf/bpf_helpers.h>
#include </home/parallels/ebpf-verifier/linux-5.18.4/tools/lib/bpf/bpf_tracing.h>

extern int bpf_check(void * a, union bpf_attr *b, void * c);

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
	int btf_fd;
};

char _license[] SEC("license") = "GPL";

#define BTF_INFO_ENC(kind, kind_flag, vlen) \
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits) \
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz) \
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz), \
	BTF_INT_ENC(encoding, bits_offset, bits)

static int btf_load(void)
{
	struct btf_blob {
		struct btf_header btf_hdr;
		__u32 types[8];
		__u32 str;
	} raw_btf = {
		.btf_hdr = {
			.magic = BTF_MAGIC,
			.version = BTF_VERSION,
			.hdr_len = sizeof(struct btf_header),
			.type_len = sizeof(__u32) * 8,
			.str_off = sizeof(__u32) * 8,
			.str_len = sizeof(__u32),
		},
		.types = {
			/* long */
			BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 64, 8),  /* [1] */
			/* unsigned long */
			BTF_TYPE_INT_ENC(0, 0, 0, 64, 8),  /* [2] */
		},
	};
	static union bpf_attr btf_load_attr = {
		.btf_size = sizeof(raw_btf),
	};

	btf_load_attr.btf = (long)&raw_btf;
	return bpf_sys_bpf(BPF_BTF_LOAD, &btf_load_attr, sizeof(btf_load_attr));
}

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

  __u64 log_buf = (__u64) malloc(20);

  //struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  struct args *ctx = (struct args *) malloc(sizeof(struct args));
  ctx->log_buf = log_buf;
  ctx->log_size = 20;
  printf("made it\n");

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
	static union bpf_attr map_create_attr = {
		.map_type = BPF_MAP_TYPE_HASH,
		.key_size = 8,
		.value_size = 8,
		.btf_key_type_id = 1,
		.btf_value_type_id = 2,
	};
	static union bpf_attr map_update_attr = { .map_fd = 1, };
	static __u64 key = 12;
	static __u64 value = 34;
	static union bpf_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insn_cnt = sizeof(insns) / sizeof(insns[0]),
	};
	int ret;

  // added:
  ret = 10;

	// ret = btf_load();
	// if (ret <= 0)
	// 	return ret;

	ctx->btf_fd = ret;
	map_create_attr.max_entries = ctx->max_entries;
	map_create_attr.btf_fd = ret;

	prog_load_attr.license = (long) license;
	prog_load_attr.insns = (long) insns;
	prog_load_attr.log_buf = ctx->log_buf;
	prog_load_attr.log_size = ctx->log_size;
	prog_load_attr.log_level = 1;
  printf("second milestone\n");

	// ret = bpf_sys_bpf(BPF_MAP_CREATE, &map_create_attr, sizeof(map_create_attr));
	// if (ret <= 0)
	// 	return ret;
	// ctx->map_fd = ret;
	// insns[3].imm = ret;
  // printf("third milestone\n");

	// map_update_attr.map_fd = ret;
	// map_update_attr.key = (long) &key;
	// map_update_attr.value = (long) &value;
	// ret = bpf_sys_bpf(BPF_MAP_UPDATE_ELEM, &map_update_attr, sizeof(map_update_attr));
	// if (ret < 0)
	// 	return ret;
  size_t size = sizeof(prog_load_attr);
  printf("mid: %d \n", size);

	ret = bpf_sys_bpf(5, &prog_load_attr, size);
	if (ret <= 0)
		return ret;
	ctx->prog_fd = ret;
	return 1;

  printf("fourth milestone\n");

  // static char license[] = "GPL";
  // static struct bpf_insn insns[] = {
	// 	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	// 	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	// 	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	// 	BPF_LD_MAP_FD(BPF_REG_1, 0),
	// 	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	// 	BPF_MOV64_IMM(BPF_REG_0, 0),
	// 	BPF_EXIT_INSN(),
	// };

  // static union bpf_attr prog_load_attr = {
	// 	.prog_type = BPF_PROG_TYPE_XDP,
	// 	.insn_cnt = sizeof(insns) / sizeof(insns[0]),
	// };

  // prog_load_attr.license = (long) license;
	// prog_load_attr.insns = (long) insns;

  // // convert prog_load_attr to bpfptr_t???
  // // size = sizeof(prog_load_attr)
  // union bpf_attr attr;
  // // it does some checks ....
  // // makes sure size is actually correct? --> takes the min
  // // copies attributes from user space --> can probably skip
  // // calls security_bpf() --> no idea what this really is for
  // // calls bpf_prog_load(&attr, uattr) --> not sure why both attr things are necessary?

  // bpf_sys_bpf(BPF_PROG_LOAD, &prog_load_attr, sizeof(prog_load_attr));

  // // 3. BPF_CALL_3(bpf_sys_bpf) ---> __sys_bpf(cmd, KERNEL_BPFPTR(attr), attr_size)
  // // 4. creates union bpf_attr (copies stuff from that bpfptr uattr)
  // // 5. checks size/updates
  // // 6. security_bpf()?
  // // 7. calls bpf_prog_load(&attr, uattr);
  // // 8. somehow creates the bpf_prog object and then finally calls the verifier

  // // struct bpf_prog *prog = (struct bpf_prog *) malloc(sizeof(struct bpf_prog));
  // // prog->pages = 5;

  // // union bpf_attr at = { 7 };
  // // bpf_check(&prog, &at, NULL);
  // return 0;
}
