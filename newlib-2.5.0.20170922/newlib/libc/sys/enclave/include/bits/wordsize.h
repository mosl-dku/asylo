#ifndef _BITS_WORDSIZE_H_
#define _BITS_WORDSIZE_H_

/* Determine the wordsize from the preprocessor defines.  */

#if defined __x86_64__ && !defined __ILP32__
# define __WORDSIZE 64
#else
# define __WORDSIZE 32
#endif

#endif  // _BITS_WORDSIZE_H_
