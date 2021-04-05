#ifndef _XATTR_H_
#define _XATTR_H_

#include <sys/types.h>

#define XATTR_CREATE 1
#define XATTR_REPLACE 2

#ifdef __cplusplus
extern "C" {
#endif

ssize_t getxattr(const char *path, const char *name, void *value, size_t size);
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
ssize_t fgetxattr(int fd, const char *name, void *value, size_t size);

int setxattr(const char *path, const char *name, const void *value, size_t size,
             int flags);
int lsetxattr(const char *path, const char *name, const void *value,
              size_t size, int flags);
int fsetxattr(int fd, const char *name, const void *value, size_t size,
              int flags);

ssize_t listxattr(const char *path, char *list, size_t size);
ssize_t llistxattr(const char *path, char *list, size_t size);
ssize_t flistxattr(int fd, char *list, size_t size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // _XATTR_H_
