// #include "header_stubs/file.h"

// int next_fd = BASE_FD;
// struct anon_fd_info * fds[FDS_SIZE];

// int anon_inode_getfd(const char *name, const void *fops,
// 		     void *priv, int flags) {
// 					int i = next_fd - BASE_FD;
// 					fds[i] = (struct anon_fd_info *)malloc(sizeof(struct anon_fd_info));
// 					fds[i]->name = name;
// 					fds[i]->fops = fops;
// 					fds[i]->priv = priv;
// 					fds[i]->flags = flags;
// 					return next_fd++;
//  }

// struct fd fdget(unsigned int fd) {
//   return {0, 0};
// }

// void fdput(struct fd fd) {

// }
#include <linux/types.h>
#include "/home/parallels/ebpf-verifier/linux/src/include/linux/fs.h"


// int main() {
// 	int a = sizeof(struct file);
// 	return a;
// }
extern void *malloc(unsigned long);

// Really basic replacement for fd allocation
struct anon_fd_info {
	const char * name;
	const void *fops;
	void *private_data;
	int flags;
};

struct fd_info {
	struct file* file;
	unsigned int flags;
};
struct my_file;

// struct file {
// 	const struct file_operations *f_op;
// 	void * private_data;
// };
// struct file;

struct fd {
	struct file *file;
	unsigned int flags;
};

#define FDS_SIZE 100
#define BASE_FD 3
int next_fd = BASE_FD;
struct fd_info * fds[FDS_SIZE];

int my_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags) {
					int bar = MY_SILLY_LIL_CONSTATNT;
					int i = next_fd - BASE_FD;
					fds[i] = (struct fd_info *)malloc(sizeof(struct anon_fd_info));
					fds[i]->file = malloc(sizeof(struct file));
					fds[i]->file->private_data = priv;
					fds[i]->file->f_op = fops;
					fds[i]->flags = flags;
					return next_fd++;
 }

unsigned long __fdget(unsigned int fd) {

	return (unsigned long)fds[fd - BASE_FD]->file;

}// garbage

struct fd my_fdget(unsigned int fd) {
	return (struct fd){fds[fd - BASE_FD]->file, fds[fd - BASE_FD]->flags};
}
