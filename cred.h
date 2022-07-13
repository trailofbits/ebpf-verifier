#define _LINUX_CRED_H

#include <linux/uidgid.h>


// typedef unsigned int uid_t;
// typedef unsigned int gid_t;

// typedef struct {
// 	uid_t val;
// } kuid_t;

// typedef struct {
//   gid_t val;
// } kgid_t;

struct user_struct {
  kuid_t uid;
};

extern int free_uid(struct user_struct *);
extern struct cred * current_cred(void);
extern int current_uid_gid(kuid_t *, kgid_t *);

struct cred {
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */

  struct user_namespace *user_ns;
};

static struct cred c = {{1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}, NULL};

extern struct user_struct *get_current_user(void);

#define current_cred_xxx(xxx)			c.xxx

#define current_uid()		(current_cred_xxx(uid))
#define current_gid()		(current_cred_xxx(gid))
#define current_euid()		(current_cred_xxx(euid))
#define current_egid()		(current_cred_xxx(egid))
#define current_suid()		(current_cred_xxx(suid))
#define current_sgid()		(current_cred_xxx(sgid))
#define current_fsuid() 	(current_cred_xxx(fsuid))
#define current_fsgid() 	(current_cred_xxx(fsgid))
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_user()		(current_cred_xxx(user))
#define current_ucounts()	(current_cred_xxx(ucounts))
#define current_user_ns() (current_cred_xxx(user_ns))
