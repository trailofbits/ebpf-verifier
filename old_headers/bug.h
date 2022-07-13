// Results of just defining one at a time.
//#define _ASM_GENERIC_BUG_H --> lots of errors
//#define __ASM_GENERIC_BUGS_H --> no errors
//#define _ARCH_ARM64_ASM_BUG_H --> no errors
//#define __ASM_ASM_BUG_H --> no errors

#define _ASM_GENERIC_BUG_H

extern void abort(void);

#define BUG() do { \
	panic("BUG!"); \
} while (0)

#ifdef CONFIG_GENERIC_BUG
struct bug_entry {
#ifndef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	unsigned long	bug_addr;
#else
	signed int	bug_addr_disp;
#endif
#ifdef CONFIG_DEBUG_BUGVERBOSE
#ifndef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	const char	*file;
#else
	signed int	file_disp;
#endif
	unsigned short	line;
#endif
	unsigned short	flags;
};
#endif	/* CONFIG_GENERIC_BUG */

#define BUGFLAG_WARNING (1 << 0)

// TODO --> actually add in user space assert logic for these


#define __BUG_FLAGS(flags) abort(void);
#define BUG_ON(condition) false
#define __WARN_FLAGS(flags) abort(void);


#define WARN_ON(condition) 1
#define WARN(condition, format...) false
#define WARN_ONCE(condition, format...) false
#define WARN_TAINT(condition, taint, format...) abort(void)
#define WARN_ON_ONCE(condition) false


#define _LINUX_BUG_H
#define _LINUX_BUILD_BUG_H
#define _TOOLS_PERF_LINUX_BUG_H

#define BUILD_BUG_ON(condition) false
#define BUILD_BUG_ON_ZERO(e) 0
#define BUILD_BUG_ON_INVALID(e) false
#define BUILD_BUG_ON_MSG(cond, msg) true
#define __BUILD_BUG_ON_NOT_POWER_OF_2(n) BUILD_BUG_ON(true)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n) BUILD_BUG_ON(true)
#define BUILD_BUG() 0

#define static_assert(expr, ...) _Static_assert(expr, "")


#define _ARCH_ARM64_ASM_BUG_H
#define __ASM_GENERIC_BUGS_H
#define __ASM_ASM_BUG_H

