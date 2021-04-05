#ifndef THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_NL_TYPES_H_
#define THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_NL_TYPES_H_

#include <features.h>
#include <stdlib.h>

#define NL_SETD 1

#define NL_CAT_LOCALE 1

typedef void *nl_catd;

#ifdef __cplusplus
extern "C" {
#endif

int catclose(nl_catd);
char *catgets(nl_catd, int, int, const char *);
nl_catd catopen(const char *, int);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_NL_TYPES_H_
