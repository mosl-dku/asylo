#ifndef _FEATURES_H
#define _FEATURES_H

# include <sys/features.h>

#define hidden __attribute__((__visibility__("hidden")))
#define weak_alias(old, new) \
  extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))


#endif  // _FEATURES_H
