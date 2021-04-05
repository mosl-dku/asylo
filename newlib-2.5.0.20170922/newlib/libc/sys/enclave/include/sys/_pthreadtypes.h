#ifndef _SYS__PTHREADTYPES_H
#define _SYS__PTHREADTYPES_H

#include <stdbool.h>

typedef uintptr_t pthread_t;

typedef struct __pthread_list_node_t __pthread_list_node_t;

struct __pthread_list_node_t {
  pthread_t _thread_id;
  __pthread_list_node_t* _next;
};

typedef struct __pthread_list_t {
  __pthread_list_node_t *_first;
} __pthread_list_t;

#define PTHREAD_CREATE_JOINABLE 0x00
#define PTHREAD_CREATE_DETACHED 0x01
#define PTHREAD_KEYS_MAX 64

typedef struct { uint32_t detach_state; } pthread_attr_t;

typedef uint32_t pthread_key_t;

typedef volatile uint32_t pthread_spinlock_t;

typedef struct {
  size_t _refcount;
  uint32_t _control;
  pthread_spinlock_t _lock;
  pthread_t _owner;
  __pthread_list_t _queue;
  int32_t *_untrusted_wait_queue;
} pthread_mutex_t;

#define _ASYLO_PTHREAD_MUTEX_TRANSITIONAL_FLAG 1
#define _ASYLO_PTHREAD_COND_TRANSITIONAL_FLAG 1
#define _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG 1
#define PTHREAD_T_NULL ((pthread_t)(NULL))
#define PTHREAD_LIST_INITIALIZER \
  { NULL }
#define PTHREAD_SPINLOCK_INITIALIZER 0x00
#define PTHREAD_MUTEX_NONRECURSIVE 0x01
#define PTHREAD_MUTEX_RECURSIVE 0x02
#define PTHREAD_WAIT_QUEUE_INITIALIZER ((int32_t *)(NULL))
#define PTHREAD_MUTEX_NONRECURSIVE_INITIALIZER                   \
  {                                                              \
    0, PTHREAD_MUTEX_NONRECURSIVE, PTHREAD_SPINLOCK_INITIALIZER, \
        PTHREAD_T_NULL, PTHREAD_LIST_INITIALIZER,                \
        PTHREAD_WAIT_QUEUE_INITIALIZER                           \
  }
#define PTHREAD_MUTEX_RECURSIVE_INITIALIZER                                   \
  {                                                                           \
    0, PTHREAD_MUTEX_RECURSIVE, PTHREAD_SPINLOCK_INITIALIZER, PTHREAD_T_NULL, \
        PTHREAD_LIST_INITIALIZER, PTHREAD_WAIT_QUEUE_INITIALIZER              \
  }
#define PTHREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_NONRECURSIVE_INITIALIZER

typedef struct { unsigned char _dummy; } pthread_mutexattr_t;

typedef struct {
  pthread_mutex_t _mutex;
  bool _ran;
} pthread_once_t;

#define PTHREAD_ONCE_INIT \
  { PTHREAD_MUTEX_NONRECURSIVE_INITIALIZER, false }

typedef struct {
  pthread_spinlock_t _lock;
  __pthread_list_t _queue;
  int32_t *_untrusted_wait_queue;
} pthread_cond_t;

#define PTHREAD_COND_INITIALIZER                            \
  {                                                         \
    PTHREAD_SPINLOCK_INITIALIZER, PTHREAD_LIST_INITIALIZER, \
        PTHREAD_WAIT_QUEUE_INITIALIZER                      \
  }

typedef struct { unsigned char _dummy; } pthread_condattr_t;

typedef struct {
  pthread_spinlock_t _lock;
  pthread_t _write_owner;
  uint32_t _reader_count;
  __pthread_list_t _queue;
  int32_t *_untrusted_wait_queue;
} pthread_rwlock_t;

#define PTHREAD_RWLOCK_INITIALIZER                                             \
  {                                                                            \
    PTHREAD_SPINLOCK_INITIALIZER, PTHREAD_T_NULL, 0, PTHREAD_LIST_INITIALIZER, \
        PTHREAD_WAIT_QUEUE_INITIALIZER                                         \
  }

typedef struct { unsigned char _dummy; } pthread_rwlockattr_t;

enum thread_state {
  __THREAD_QUEUED,
  __THREAD_RUNNING,
  __THREAD_DONE,
  __THREAD_JOINED,
};

struct __cleanup {
  void (*function)(void *);
  void *argument;
  struct __cleanup *next;
};

struct __pthread_info {
  pthread_t thread_id;
  struct __pthread_info *self;
  uint64_t tid;
  size_t tls_size;
  pthread_attr_t *attr;
  void **tsd;
  // Guards thread state.
  pthread_mutex_t lock;
  pthread_cond_t state_change_cond;
  enum thread_state state;
  bool detached;
  void *result;
  struct __cleanup *cleanup;
};

#endif  // _SYS__PTHREADTYPES_H
