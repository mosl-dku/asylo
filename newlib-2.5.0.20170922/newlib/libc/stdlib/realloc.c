#ifdef MALLOC_PROVIDED
int _dummy_calloc = 1;
#else
/* realloc.c -- a wrapper for realloc_r.  */

#include <_ansi.h>
#include <reent.h>
#include <stdlib.h>
#include <malloc.h>

#ifndef _REENT_ONLY

#ifdef __ASYLO__
static void* (*realloc_hook)(void*, size_t, void*) = NULL;
static void* realloc_pool = NULL;

void
_DEFUN (set_realloc_hook, (custom_realloc, pool),
        void* (*custom_realloc)(void*, size_t, void*) _AND
        void* pool)
{
  realloc_hook = custom_realloc;
  realloc_pool = pool;
}
#endif  // __ASYLO__

_PTR
_DEFUN (realloc, (ap, nbytes),
	_PTR ap _AND
	size_t nbytes)
{
#ifdef __ASYLO__
  if (realloc_hook)
  {
    return realloc_hook(ap, nbytes, realloc_pool);
  }
#endif  // __ASYLO__
  return _realloc_r (_REENT, ap, nbytes);
}

#endif
#endif /* MALLOC_PROVIDED */
