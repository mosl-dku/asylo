#include <sys/syscall.h>
#include <sys/xattr.h>

#include "enclave_syscalls.h"

ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)name, (uint64_t)value, size};
  return enclave_syscall(SYS_getxattr, args, 4);
}

ssize_t lgetxattr(const char *path, const char *name, void *value,
                  size_t size) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)name, (uint64_t)value, size};
  return enclave_syscall(SYS_lgetxattr, args, 4);
}

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) {
  uint64_t args[] = {fd, (uint64_t)name, (uint64_t)value, size};
  return enclave_syscall(SYS_fgetxattr, args, 4);
}

int setxattr(const char *path, const char *name, const void *value, size_t size,
             int flags) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)name, (uint64_t)value, size,
    flags};
  return enclave_syscall(SYS_setxattr, args, 5);
}

int lsetxattr(const char *path, const char *name, const void *value,
              size_t size, int flags) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)name, (uint64_t)value, size,
    flags};
  return enclave_syscall(SYS_lsetxattr, args, 5);
}

int fsetxattr(int fd, const char *name, const void *value, size_t size,
              int flags) {
  uint64_t args[] = {fd, (uint64_t)name, (uint64_t)value, size, flags};
  return enclave_syscall(SYS_fsetxattr, args, 5);
}

ssize_t listxattr(const char *path, char *list, size_t size) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)list, size};
  return enclave_syscall(SYS_listxattr, args, 3);
}

ssize_t llistxattr(const char *path, char *list, size_t size) {
  uint64_t args[] = {(uint64_t)path, (uint64_t)list, size};
  return enclave_syscall(SYS_llistxattr, args, 3);
}

ssize_t flistxattr(int fd, char *list, size_t size) {
  uint64_t args[] = {fd, (uint64_t)list, size};
  return enclave_syscall(SYS_flistxattr, args, 3);
}
