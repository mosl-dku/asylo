#ifndef _UNISTD_H_
#define _UNISTD_H_

#include <sys/unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

long int syscall(long int sys_no, ...);

#ifdef __cplusplus
}
#endif

#endif /* _UNISTD_H_ */
