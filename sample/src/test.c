#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>

// TODO: is this the best function to stub out or should it be a narrower
// one like bpf_prog__load_skeleton???
// int __bpf_object__load_skeleton(struct bpf_object_skeleton *skeleton) {
//   printf("name: %s\n", skeleton->name);
//   if (skeleton == (struct bpf_object_skeleton *)(void *)0x0)
//     return 2;
//   return -1;
// }

// bpf_object_load_prog
// static int bpf_object_load_prog(struct bpf_object *obj, struct bpf_program *prog,
				//const char *license, __u32 kern_ver)
// bpf_object_load_prog_instance
// bpf_prog_load

int __bpf_prog_load(enum bpf_prog_type type, const char *prog_name, \
                    const char *license, struct bpf_insn *insns, \
                    int insns_cnt, struct bpf_prog_load_opts *opts) {

                    printf("name: %s\n", prog_name);
                    printf("insns_cnt: %d\n", insns_cnt);

                    return 999;


                    }
