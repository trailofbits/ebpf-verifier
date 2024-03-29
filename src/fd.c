#include <stddef.h>
#include <stdlib.h>

struct file_operations;

#define FDS_SIZE 100
#define BASE_FD 3
#define MAX_FD FDS_SIZE+BASE_FD-1
int next_fd = BASE_FD;

struct fd {
	struct file *file;
	unsigned int flags;
};

static struct fd fds[FDS_SIZE];

extern int size_of_file(void);
extern void set_private_data(void *priv, struct file *file);
extern void init_file(struct file *file, int flags, const struct file_operations *fop);
extern void *kcalloc(size_t n, size_t size);

struct fd fdget(int fd) {
  if (fd < BASE_FD) {
    abort();
  }
  return fds[fd - BASE_FD];
}
void fdput(void) {return; }
void fput(void) { abort(); }

void anon_inode_getfile(void) { abort(); }

int anon_inode_getfd(const char *name, const void *fops, void *priv, int flags) {
  struct file * f = (struct file *)kcalloc(1, size_of_file());
  if (next_fd > MAX_FD) {
    abort();
  }
  init_file(f, flags, fops);
  set_private_data(priv, f);
  int i = next_fd - BASE_FD;
  fds[i].file = f;
  fds[i].flags = flags;
  return next_fd++;
}
