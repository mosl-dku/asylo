#ifndef _LIMITS_H_
#define _LIMITS_H_

// Be sure to include gcc's limits.h if we haven't already.
#if defined(__GNUC__) && !defined(_GCC_LIMITS_H_)
#include_next <limits.h>
#endif

#include <sys/syslimits.h>

#endif  // _LIMITS_H_
