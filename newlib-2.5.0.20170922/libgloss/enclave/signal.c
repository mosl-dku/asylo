#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>

#include "enclave_syscalls.h"

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  uint64_t args[] = {signum, (uint64_t)act, (uint64_t)oldact, sizeof(sigset_t)};
  return enclave_syscall(SYS_rt_sigaction, args, 4);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  uint64_t args[] = {how, (uint64_t)set, (uint64_t)oldset, sizeof(sigset_t)};
  return enclave_syscall(SYS_rt_sigprocmask, args, 4);
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
  return sigprocmask(how, set, oldset);
}

// Registers a signal handler for |signum| with |handler|.
//
// This method is a special case of sigaction. It calls sigaction with only
// sa_handler in |act| field set.
sighandler_t signal(int signum, sighandler_t handler) {
  struct sigaction act;
  act.sa_handler = handler;
  sigemptyset(&act.sa_mask);
  struct sigaction oldact;
  if (sigaction(signum, &act, &oldact)) {
    // Errno is set by sigaction.
    return SIG_ERR;
  }
  return oldact.sa_handler;
}
