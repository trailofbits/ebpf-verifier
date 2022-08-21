// #include <stdio.h>
#include <stdlib.h>

#define FDS_SIZE 100
#define BASE_FD 3
#define MAX_FD FDS_SIZE+BASE_FD-1
int next_fd = BASE_FD;

struct fd {
	struct file *file;
	unsigned int flags;
};
struct fd fds[FDS_SIZE];

extern int size_of_file(void);
extern void set_private_data(void *priv, struct file *file);
extern void init_file(struct file *file, int flags, const struct file_operations *fop);

void init_pseudo_filesys(void) {
  // printf("sizeof file: %d\n", size_of_file());
}

struct fd fdget(int fd) {
  if (fd < BASE_FD) {
    // printf("invalid fd\n");
    abort();
  }
  return fds[fd - BASE_FD];
}
void fdput(void) {return; }
void fput(void) { abort(); }

void anon_inode_getfile(void) { abort(); }

int anon_inode_getfd(const char *name, const void *fops, void *priv, int flags) {
  struct file * f = (struct file *)calloc(1, size_of_file());
  if (next_fd > MAX_FD) {
    // printf("out of fds\n");
    abort();
  }
  init_file(f, flags, fops);
  set_private_data(priv, f);
  int i = next_fd - BASE_FD;
  fds[i].file = f;
  fds[i].flags = flags;
  return next_fd++;
}


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
// #include <linux/types.h>
// #include "/home/parallels/ebpf-verifier/linux/src/include/linux/fs.h"


// // int main() {
// // 	int a = sizeof(struct file);
// // 	return a;
// // }
// extern void *malloc(unsigned long);

// // Really basic replacement for fd allocation
// struct anon_fd_info {
// 	const char * name;
// 	const void *fops;
// 	void *private_data;
// 	int flags;
// };

// struct fd_info {
// 	struct file* file;
// 	unsigned int flags;
// };
// struct my_file;

// // struct file {
// // 	const struct file_operations *f_op;
// // 	void * private_data;
// // };
// // struct file;

// struct fd {
// 	struct file *file;
// 	unsigned int flags;
// };

// #define FDS_SIZE 100
// #define BASE_FD 3
// int next_fd = BASE_FD;
// struct fd_info * fds[FDS_SIZE];

// int my_getfd(const char *name, const struct file_operations *fops,
// 		     void *priv, int flags) {
// 					int bar = MY_SILLY_LIL_CONSTATNT;
// 					int i = next_fd - BASE_FD;
// 					fds[i] = (struct fd_info *)malloc(sizeof(struct anon_fd_info));
// 					fds[i]->file = malloc(sizeof(struct file));
// 					fds[i]->file->private_data = priv;
// 					fds[i]->file->f_op = fops;
// 					fds[i]->flags = flags;
// 					return next_fd++;
//  }

// unsigned long __fdget(unsigned int fd) {

// 	return (unsigned long)fds[fd - BASE_FD]->file;

// }// garbage

// struct fd my_fdget(unsigned int fd) {
// 	return (struct fd){fds[fd - BASE_FD]->file, fds[fd - BASE_FD]->flags};
// }
