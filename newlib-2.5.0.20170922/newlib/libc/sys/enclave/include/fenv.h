#ifndef THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_FENV_H_
#define THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_FENV_H_

typedef void *fenv_t;
typedef int fexcept_t;

#define FE_DIVBYZERO 1
#define FE_INEXACT 2
#define FE_INVALID 4
#define FE_OVERFLOW 8
#define FE_UNDERFLOW 16
#define FE_ALL_EXCEPT \
  (FE_DIVBYZERO | FE_INEXACT | FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW)

#define FE_DOWNWARD 1
#define FE_TONEAREST 2
#define FE_TOWARDZERO 3
#define FE_UPWARD 4

int feclearexcept(int);
int fegetexceptflag(fexcept_t *, int);
int feraiseexcept(int);
int fesetexceptflag(const fexcept_t *, int);
int fetestexcept(int);
int fegetround(void);
int fesetround(int);
int fegetenv(fenv_t *);
int feholdexcept(fenv_t *);
int fesetenv(const fenv_t *);
int feupdateenv(const fenv_t *);

#endif  // THIRD_PARTY_NEWLIB_SRC_NEWLIB_LIBC_SYS_ENCLAVE_INCLUDE_FENV_H_
