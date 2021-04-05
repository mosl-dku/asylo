#ifndef _SYS_RESOURCE_H_
#define _SYS_RESOURCE_H_

#include <sys/time.h>

#if defined (__ASYLO__) && defined( __cplusplus)
extern "C" {
#endif

#define	RUSAGE_SELF	0		/* calling process */
#define	RUSAGE_CHILDREN	-1		/* terminated child processes */

struct rusage {
  	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
};

int	_EXFUN(getrusage, (int, struct rusage*));

#if defined(__ASYLO__) && defined( __cplusplus)
}  // extern "C"
#endif

#endif

