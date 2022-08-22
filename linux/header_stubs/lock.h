#define _LINUX_LOCAL_LOCK_H

typedef struct {} local_lock_t;

#define INIT_LOCAL_LOCK(lock) {}
#define local_lock(lock)
#define local_unlock(lock)
