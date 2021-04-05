#include <grp.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>

#include "enclave_syscalls.h"

void _exit(int rc) {
  enclave_exit(rc);
}

int _close(int fildes) {
  uint64_t args[] = {(uint64_t)fildes};
  return enclave_syscall(SYS_close, args, 1);
}

int _execve(const char *name, char *const argv[], char *const env[]) {
  uint64_t args[] = {(uint64_t)name,
                   (uint64_t)argv,
                   (uint64_t)env};
  return enclave_syscall(SYS_execve, args, 3);
}

int _fcntl(int fd, int cmd, int64_t arg) {
  uint64_t args[] = {(uint64_t)fd, (uint64_t)cmd,
                   (uint64_t)arg};
  return enclave_syscall(SYS_fcntl, args, 3);
}

int _fork() {
  return enclave_fork();
}

int _fstat(int fildes, struct stat *st) {
  uint64_t args[] = {(uint64_t)fildes,
                   (uint64_t)st};
  return enclave_syscall(SYS_fstat, args, 2);
}

int _getpid() {
  return enclave_syscall(SYS_getpid, 0, 0);
}

int _gettimeofday(struct timeval *ptimeval, void *ptimezone) {
  uint64_t args[] = {(uint64_t)ptimeval,
                   (uint64_t)ptimezone};
  return enclave_syscall(SYS_gettimeofday, args, 2);
}

int _kill(int pid, int sig) {
  uint64_t args[] = {(uint64_t)pid, (uint64_t)sig};
  return enclave_syscall(SYS_kill, args, 2);
}

int _link(const char *existing, const char *new_link) {
  uint64_t args[] = {(uint64_t)existing,
                   (uint64_t)new_link};
  return enclave_syscall(SYS_link, args, 2);
}

int _lseek(int file, int ptr, int dir) {
  uint64_t args[] = {(uint64_t)file, (uint64_t)ptr,
                   (uint64_t)dir};
  return enclave_syscall(SYS_lseek, args, 3);
}

int _mkdir(const char *pathname, mode_t mode) {
  uint64_t args[] = {(uint64_t)pathname, mode};
  return enclave_syscall(SYS_mkdir, args, 2);
}

int _open(const char *file, int flags, int mode) {
  uint64_t args[] = {(uint64_t)file,
                     (uint64_t)flags, mode};
  return enclave_syscall(SYS_open, args, 3);
}

int _read(int file, char *ptr, int len) {
  uint64_t args[] = {(uint64_t)file,
                     (uint64_t)ptr, len};
  return enclave_syscall(SYS_read, args, 3);
}

void *_sbrk(int incr) {
  return enclave_sbrk(incr);
}

int _stat(const char *file, struct stat *st) {
  uint64_t args[] = {(uint64_t)file,
                     (uint64_t)st};
  return enclave_syscall(SYS_stat, args, 2);
}

clock_t _times(struct tms *buf) {
  uint64_t args[] = {(uint64_t)buf};
  return enclave_syscall(SYS_times, args, 1);
}

int _unlink(const char *name) {
  uint64_t args[] = {(uint64_t)name};
  return enclave_syscall(SYS_unlink, args, 1);
}

int _wait(int *status) {
  return enclave_wait(status);
}

int _write(int file, const char *ptr, int len) {
  uint64_t args[] = {(uint64_t)file,
                     (uint64_t)ptr, len};
  return enclave_syscall(SYS_write, args, 3);
}
