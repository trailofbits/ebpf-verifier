#include <linux/fs.h>

inline int size_of_file(void) { return sizeof(struct file); }

inline void set_private_data(void *priv, struct file *file) { file->private_data = priv; }
inline void set_f_op(const void *fops, struct file *file) { file->f_op = fops; }

inline void init_file(struct file *file, int flags, const struct file_operations *fop) {
  // f->f_cred  = ???
  // ignoring initializing f_count, f_woner.lock, f_lock, f_pos_lock
  file->f_flags = flags;
  file->f_mode = OPEN_FMODE(flags);
  if ((file->f_mode & FMODE_READ) &&
	     likely(fop->read || fop->read_iter))
		file->f_mode |= FMODE_CAN_READ;
	if ((file->f_mode & FMODE_WRITE) &&
	     likely(fop->write || fop->write_iter))
		file->f_mode |= FMODE_CAN_WRITE;
	file->f_mode |= FMODE_OPENED;
  file->f_op = fop;
}
