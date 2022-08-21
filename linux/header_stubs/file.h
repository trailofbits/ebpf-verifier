#define __LINUX_FILE_H

struct file;
struct task_struct;
// struct fd;

extern void fput(struct file *);
extern void put_unused_fd(unsigned int fd);
extern void fd_install(unsigned int fd, struct file *file);
extern int get_unused_fd_flags(unsigned flags);
extern struct file *fget_task(struct task_struct *task, unsigned int fd);

struct fd {
	struct file *file;
	unsigned int flags;
};

extern struct fd fdget(unsigned int fd);
extern void fdput(struct fd fd);



// #define _LINUX_FS_H

// #define __LINUX_FILE_H
// #define _LINUX_FS_H

// #include <uapi/linux/fs.h>
// #include <uapi/linux/fcntl.h>
// #include <linux/path.h>
// #include <linux/wait_bit.h>
// #include <linux/uidgid.h>

// #define __I_NEW			3
// #define I_CLEAR			(1 << 6)

// struct file;
// struct poll_table_struct;
// struct kiocb;
// struct inode_operations;

// struct file_operations {
// 	__poll_t (*poll) (struct file *, struct poll_table_struct *);
// };



// struct file {
// 	const struct cred * f_cred; //const struct cred	*f_cred;
// 	struct file_operations *f_op;
// 	void * private_data;
// };

// struct inode {
// 	void *i_wb; // struct bdi_writeback	*i_wb;		/* the associated cgroup wb */
// 	unsigned long		i_state;
// 	spinlock_t i_lock; //spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
// 	kuid_t			i_uid;
// };

// struct fd {
// 	struct file *file;
// 	unsigned int flags;
// };

// extern void *malloc(unsigned long);

// // extern struct fd fdget(unsigned int fd);
// // extern void fdput(struct fd fd);

// extern bool is_sync_kiocb(struct kiocb *kiocb);
// extern bool vma_is_dax(const struct vm_area_struct *vma);

// struct fd_info {
// 	struct file* file;
// 	unsigned int flags;
// };

// #define FDS_SIZE 100
// #define BASE_FD 3
// int next_fd = BASE_FD;
// struct fd_info * fds[FDS_SIZE];

// // Really basic replacement for fd allocation
// struct anon_fd_info {
// 	const char * name;
// 	const void *fops;
// 	void *private_data;
// 	int flags;
// };

// int my_anon_inode_getfd(const char *name, const void *fops,
// 		     void *priv, int flags) {
// 					int i = next_fd - BASE_FD;
// 					fds[i] = (struct fd_info *)malloc(sizeof(struct anon_fd_info));
// 					fds[i]->file = (struct file*)malloc(sizeof(struct file));
// 					fds[i]->file->private_data = priv;
// 					fds[i]->flags = flags;
// 					return next_fd++;
//  }

// struct fd fdget(unsigned int fd) {
// 	return (struct fd){fds[fd - BASE_FD]->file, fds[fd - BASE_FD]->flags};
// }

// void fdput(struct fd fd) {
// 	return;
// }
