#ifndef THIRD_PARTY_NEWLIB_SRC_LIBGLOSS_ENCLAVE_ENCLAVE_SYSCALLS_H_
#define THIRD_PARTY_NEWLIB_SRC_LIBGLOSS_ENCLAVE_ENCLAVE_SYSCALLS_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

void enclave_exit(int rc);
int enclave_fork();
void *enclave_sbrk(int incr);
int enclave_wait(int *status);

int64_t enclave_syscall(int sysno, uint64_t args[], size_t nargs);

#if defined(__cplusplus)
}
#endif

#endif  // THIRD_PARTY_NEWLIB_SRC_LIBGLOSS_ENCLAVE_ENCLAVE_SYSCALLS_H_
