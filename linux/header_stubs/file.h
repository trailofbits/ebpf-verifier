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
