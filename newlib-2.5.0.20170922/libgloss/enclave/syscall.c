#include <errno.h>
#include <unistd.h>

long int syscall(long int sys_no, ...) {
  errno = ENOSYS;
  return -1;
}
