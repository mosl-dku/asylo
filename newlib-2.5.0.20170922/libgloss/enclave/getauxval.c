#include <sys/auxv.h>
#include <errno.h>

unsigned long getauxval(unsigned long item) {
  errno = ENOSYS;
  return -1;
}
