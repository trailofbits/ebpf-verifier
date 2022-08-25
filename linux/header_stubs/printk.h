#ifdef __v5_18__
#define __KERNEL_PRINTK__

#define pr_emerg(fmt, ...)
#define pr_alert(fmt, ...)
#define pr_crit(fmt, ...)
#define pr_err(fmt, ...)
#define pr_notice(fmt, ...)
#define pr_cont(fmt, ...)
#define pr_info_once(fmt, ...)
#define pr_warn_once(fmt, ...)
#define pr_debug(fmt, ...)
#define pr_warn(fmt, ...)
#define print_hex_dump(fmt, ...)
#define printk(fmt, ...)
// read_sysreg
#endif /* __v5_18__ */
