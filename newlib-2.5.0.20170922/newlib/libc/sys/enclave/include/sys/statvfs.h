#ifndef THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATVFS_H_
#define THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATVFS_H_

#include <sys/types.h>
#include <sys/_statfs.h>

struct statvfs {
  unsigned long  f_bsize;    /* Filesystem block size */
  unsigned long  f_frsize;   /* Fragment size */
  fsblkcnt_t     f_blocks;   /* Size of fs in f_frsize units */
  fsblkcnt_t     f_bfree;    /* Number of free blocks */
  fsblkcnt_t     f_bavail;   /* Number of free blocks for unprivileged users */
  fsfilcnt_t     f_files;    /* Number of inodes */
  fsfilcnt_t     f_ffree;    /* Number of free inodes */
  fsfilcnt_t     f_favail;   /* Number of free inodes for unprivileged users */
  struct { int __val[2]; }  f_fsid;     /* Filesystem ID */
  unsigned long  f_flag;     /* Mount flags */
  unsigned long  f_namemax;  /* Maximum filename length */
};

#ifdef __cplusplus
extern "C" {
#endif

int statvfs(const char *path, struct statvfs *statvfs_buffer);
int fstatvfs(int fd, struct statvfs *statvfs_buffer);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATVFS_H_
