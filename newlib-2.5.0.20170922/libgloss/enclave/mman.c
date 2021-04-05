/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <sys/mman.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>


// Simulated page size, used by the POSIX wrappers.
static const size_t kPageSize = 4096;


void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  if (addr || prot != (PROT_READ | PROT_WRITE) ||
      flags != (MAP_ANONYMOUS | MAP_PRIVATE) || fd != -1 || offset != 0) {
    errno = ENOSYS;
    return MAP_FAILED;
  }
  void *ptr = NULL;
  if (posix_memalign(&ptr, kPageSize, length)) {
    return MAP_FAILED;
  }

  memset(ptr, 0, length);
  return ptr;
}

int munmap(void *addr, size_t length) {
  free(addr);
  return 0;
}

// Declared here instead of from #include <malloc.h> due to clang errors.
void *memalign(size_t alignment, size_t size);

int posix_memalign(void **memptr, size_t alignment, size_t size) {
  // The spec says passing a size of 0 should either return a null pointer or
  // a valid freeable pointer.
  // The latter behavior is used by some applications to check that
  // allocations can succeed.

  void *ptr = memalign(alignment, size);

  // From the man page: "On Linux (and other systems), posix_memalign() does not
  // modify memptr on failure.  A requirement standardizing this behavior was
  // added in POSIX.1-2016."
  if (!ptr) {
    return ENOMEM;
  }

  *memptr = ptr;
  return 0;
}

int mlock(const void *addr, size_t len) {
  errno = ENOSYS;
  return -1;
}

int mlock2(const void *addr, size_t len, int flags) {
  errno = ENOSYS;
  return -1;
}

int munlock(const void *addr, size_t len) {
  errno = ENOSYS;
  return -1;
}

int mlockall(int flags) {
  errno = ENOSYS;
  return -1;
}

int munlockall(void) {
  errno = ENOSYS;
  return -1;
}

// mprotect is weak to allow an optional definition with Intel's trts_mprotect.
__attribute__((weak))
int mprotect(void *addr, size_t len, int prot) {
  errno = ENOSYS;
  return -1;
}

int madvise(void *addr, size_t len, int advice) {
  errno = ENOSYS;
  return -1;
}

int mincore(void *addr, size_t len, unsigned char *vec) {
  errno = ENOSYS;
  return -1;
}
