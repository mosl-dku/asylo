#ifndef THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS__STATFS_H_
#define THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS__STATFS_H_

#include <features.h>

#define ST_NOSUID      (1 << 5)
#define ST_RDONLY      (1 << 6)

// The following flags are only available for with the _GNU_SOURCE extensions.
#ifdef __GNU_VISIBLE
#define ST_MANDLOCK    (1 << 0)
#define ST_NOATIME     (1 << 1)
#define ST_NODEV       (1 << 2)
#define ST_NODIRATIME  (1 << 3)
#define ST_NOEXEC      (1 << 4)
#define ST_RELATIME    (1 << 7)
#define ST_SYNCHRONOUS (1 << 8)
#define ST_WRITE       (1 << 9)
#define ST_APPEND      (1 << 10)
#define ST_IMMUTABLE   (1 << 11)
#endif

#endif  // THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS__STATFS_H_
