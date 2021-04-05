#ifndef THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATFS_H_
#define THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATFS_H_

#include <stdint.h>
#include <sys/_statfs.h>

struct statfs {
  int64_t f_type; /* type of file system (see below) */
  int64_t f_bsize; /* optimal transfer block size */
  uint64_t f_blocks; /* total data blocks in file system */
  uint64_t f_bfree; /* free blocks in fs */
  uint64_t f_bavail; /* free blocks available to unprivileged user */
  uint64_t f_files; /* total file nodes in file system */
  uint64_t f_ffree; /* free file nodes in fs */
  struct { int __val[2]; } f_fsid; /* file system id */
  int64_t f_namelen; /* maximum length of filenames */
  int64_t f_frsize; /* fragment size (since Linux 2.6) */
  int64_t f_flags;    /* Filesystem mount flags (since Linux 2.6.36) */
  int64_t f_spare[4];
};

#define ADFS_SUPER_MAGIC 0xADF5
#define AFFS_SUPER_MAGIC 0xADFF
#define BEFS_SUPER_MAGIC 0x42465331
#define BFS_MAGIC 0x1BADFACE
#define CIFS_MAGIC_NUMBER 0xFF534D42
#define CODA_SUPER_MAGIC 0x73757245
#define COH_SUPER_MAGIC 0x012FF7B7
#define CRAMFS_MAGIC 0x28CD3D45
#define DEVFS_SUPER_MAGIC 0x1373
#define EFS_SUPER_MAGIC 0x00414A53
#define EXT_SUPER_MAGIC 0x137D
#define EXT2_OLD_SUPER_MAGIC 0xEF51
#define EXT2_SUPER_MAGIC 0xEF53
#define EXT3_SUPER_MAGIC 0xEF53
#define EXT4_SUPER_MAGIC 0xEF53
#define HFS_SUPER_MAGIC 0x4244
#define HPFS_SUPER_MAGIC 0xF995E849
#define HUGETLBFS_MAGIC 0x958458F6
#define ISOFS_SUPER_MAGIC 0x9660
#define JFFS2_SUPER_MAGIC 0x72B6
#define JFS_SUPER_MAGIC 0x3153464A
#define MINIX_SUPER_MAGIC 0x137F /* orig. minix */
#define MINIX_SUPER_MAGIC2 0x138F /* 30 char minix */
#define MINIX2_SUPER_MAGIC 0x2468 /* minix V2 */
#define MINIX2_SUPER_MAGIC2 0x2478 /* minix V2, 30 char names */
#define MSDOS_SUPER_MAGIC 0x4D44
#define NCP_SUPER_MAGIC 0x564C
#define NFS_SUPER_MAGIC 0x6969
#define NTFS_SB_MAGIC 0x5346544E
#define OPENPROM_SUPER_MAGIC 0x9FA1
#define PROC_SUPER_MAGIC 0x9FA0
#define QNX4_SUPER_MAGIC 0x002F
#define REISERFS_SUPER_MAGIC 0x52654973
#define ROMFS_MAGIC 0x7275
#define SMB_SUPER_MAGIC 0x517B
#define SYSV2_SUPER_MAGIC 0x012FF7B6
#define SYSV4_SUPER_MAGIC 0x012FF7B5
#define TMPFS_MAGIC 0x01021994
#define UDF_SUPER_MAGIC 0x15013346
#define UFS_MAGIC 0x00011954
#define USBDEVICE_SUPER_MAGIC 0x9FA2
#define VXFS_SUPER_MAGIC 0xA501FCF5
#define XENIX_SUPER_MAGIC 0x012FF7B4
#define XFS_SUPER_MAGIC 0x58465342

#ifdef __cplusplus
extern "C" {
#endif

int statfs(const char *path, struct statfs *buf);
int fstatfs(int fd, struct statfs *buf);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_SYS_STATFS_H_
