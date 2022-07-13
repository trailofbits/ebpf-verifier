#ifndef __ASM_JUMP_LABEL_H
#define __ASM_JUMP_LABEL_H

#ifndef __ASSEMBLY__

#include <linux/types.h>


#define JUMP_LABEL_NOP_SIZE		AARCH64_INSN_SIZE

static __always_inline bool arch_static_branch(struct static_key *key,
					       bool branch)
{
	return  false;
}

static __always_inline bool arch_static_branch_jump(struct static_key *key,
						    bool branch)
{
	return  false;
}

#endif  /* __ASSEMBLY__ */

#endif
