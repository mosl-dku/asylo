/* sys/signal.h */

#ifndef _SYS_SIGNAL_H
#define _SYS_SIGNAL_H
#ifdef __cplusplus
extern "C" {
#endif

#include "_ansi.h"
#include <sys/cdefs.h>
#include <sys/features.h>
#include <sys/types.h>
#include <sys/_sigset.h>
#include <sys/_timespec.h>

#if !defined(_SIGSET_T_DECLARED)
#define	_SIGSET_T_DECLARED
typedef	__sigset_t	sigset_t;
#endif

#if defined(__CYGWIN__)
#include <cygwin/signal.h>
#else

#if defined(_POSIX_REALTIME_SIGNALS) || __POSIX_VISIBLE >= 199309

/* sigev_notify values
   NOTE: P1003.1c/D10, p. 34 adds SIGEV_THREAD.  */

#define SIGEV_NONE   1  /* No asynchronous notification shall be delivered */
                        /*   when the event of interest occurs. */
#define SIGEV_SIGNAL 2  /* A queued signal, with an application defined */
                        /*  value, shall be delivered when the event of */
                        /*  interest occurs. */
#define SIGEV_THREAD 3  /* A notification function shall be called to */
                        /*   perform notification. */

/*  Signal Generation and Delivery, P1003.1b-1993, p. 63
    NOTE: P1003.1c/D10, p. 34 adds sigev_notify_function and
          sigev_notify_attributes to the sigevent structure.  */

union sigval {
  int    sival_int;    /* Integer signal value */
  void  *sival_ptr;    /* Pointer signal value */
};

#define __SI_MAX_SIZE     128
#define __SIGEV_MAX_SIZE  64
#if __WORDSIZE == 64
#define __SI_PAD_SIZE     ((__SI_MAX_SIZE / sizeof (int)) - 4)
#define __SIGEV_PAD_SIZE  ((__SIGEV_MAX_SIZE / sizeof (int)) - 4)
#else
#define __SI_PAD_SIZE     ((__SI_MAX_SIZE / sizeof (int)) - 3)
#define __SIGEV_PAD_SIZE  ((__SIGEV_MAX_SIZE / sizeof (int)) - 3)
#endif

#if __WORDSIZE == 64
#else
#endif

#if defined __x86_64__ && __WORDSIZE == 32
typedef __clock_t __attribute__ ((__aligned__ (4))) __sigchld_clock_t;
#define __SI_ALIGNMENT __attribute__ ((__aligned__ (8)))
#else
typedef __clock_t __sigchld_clock_t;
#define __SI_ALIGNMENT
#endif

struct sigevent {
  int              sigev_notify;               /* Notification type */
  int              sigev_signo;                /* Signal number */
  union sigval     sigev_value;                /* Signal value */

  union {
    int _pad[__SIGEV_PAD_SIZE];

    /* When SIGEV_SIGNAL and SIGEV_THREAD_ID set, LWP ID of the
       thread to receive the signal.  */
    __pid_t _tid;

    #if defined(_POSIX_THREADS)
    struct {
      void (*sigev_notify_function)( union sigval ); /* Notification function */
      pthread_attr_t  *sigev_notify_attributes;    /* Notification Attributes */
    } _sigev_thread;
    #endif
  } _sigev_un;
};

/* Signal Actions, P1003.1b-1993, p. 64 */
/* si_code values, p. 66 */

#define SI_USER    1    /* Sent by a user. kill(), abort(), etc */
#define SI_QUEUE   2    /* Sent by sigqueue() */
#define SI_TIMER   3    /* Sent by expiration of a timer_settime() timer */
#define SI_ASYNCIO 4    /* Indicates completion of asycnhronous IO */
#define SI_MESGQ   5    /* Indicates arrival of a message at an empty queue */

typedef struct {
  int          si_signo;    /* Signal number */
  int          si_code;     /* Cause of the signal */
  union sigval si_value;    /* Signal value */
  union {
    int _pad[__SI_PAD_SIZE];

    /* kill().  */
    struct {
      __pid_t si_pid;  /* Sending process ID.  */
      __uid_t si_uid;  /* Real user ID of sending process.  */
    } _kill;

    /* POSIX.1b timers.  */
    struct {
      int si_tid;              /* Timer ID.  */
      int si_overrun;          /* Overrun count.  */
      union sigval si_sigval;  /* Signal value.  */
    } _timer;

    /* POSIX.1b signals.  */
    struct {
      __pid_t si_pid;          /* Sending process ID.  */
      __uid_t si_uid;          /* Real user ID of sending process.  */
      union sigval si_sigval;  /* Signal value.  */
    } _rt;

    /* SIGCHLD.  */
    struct {
      __pid_t si_pid;    /* Which child.  */
      __uid_t si_uid;    /* Real user ID of sending process.  */
      int si_status;     /* Exit value or signal.  */
      __sigchld_clock_t si_utime;
      __sigchld_clock_t si_stime;
    } _sigchld;

    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
    struct {
      void *si_addr;          /* Faulting insn/memory ref.  */
      short int si_addr_lsb;  /* Valid LSB of the reported address.  */
    } _sigfault;

    /* SIGPOLL.  */
    struct {
      long int si_band;  /* Band event for SIGPOLL.  */
      int si_fd;
    } _sigpoll;

    /* SIGSYS.  */
    struct {
      void *_call_addr;    /* Calling user insn.  */
      int _syscall;        /* Triggering system call number.  */
      unsigned int _arch;  /* AUDIT_ARCH_* of syscall.  */
    } _sigsys;
  } _sifields;
} siginfo_t __SI_ALIGNMENT;

#if defined(__ASYLO__)
# define si_pid		_sifields._kill.si_pid
# define si_uid		_sifields._kill.si_uid
# define si_timerid	_sifields._timer.si_tid
# define si_overrun	_sifields._timer.si_overrun
# define si_status	_sifields._sigchld.si_status
# define si_utime	_sifields._sigchld.si_utime
# define si_stime	_sifields._sigchld.si_stime
# define si_value	_sifields._rt.si_sigval
# define si_int		_sifields._rt.si_sigval.sival_int
# define si_ptr		_sifields._rt.si_sigval.sival_ptr
# define si_addr	_sifields._sigfault.si_addr
# define si_addr_lsb	_sifields._sigfault.si_addr_lsb
# define si_band	_sifields._sigpoll.si_band
# define si_fd		_sifields._sigpoll.si_fd
# define si_call_addr 	_sifields._sigsys._call_addr
# define si_syscall	_sifields._sigsys._syscall
# define si_arch	_sifields._sigsys._arch
#endif

#endif /* defined(_POSIX_REALTIME_SIGNALS) || __POSIX_VISIBLE >= 199309 */

#if defined(__rtems__) || defined(__ASYLO__)

/*  3.3.8 Synchronously Accept a Signal, P1003.1b-1993, p. 76 */

#define SA_NOCLDSTOP 0x1   /* Do not generate SIGCHLD when children stop */
#define SA_SIGINFO   0x2   /* Invoke the signal catching function with */
                           /*   three arguments instead of one. */
#if __BSD_VISIBLE || __XSI_VISIBLE >= 4 || __POSIX_VISIBLE >= 200809
#define SA_ONSTACK   0x4   /* Signal delivery will be on a separate stack. */
#endif

/* struct sigaction notes from POSIX:
 *
 *  (1) Routines stored in sa_handler should take a single int as
 *      their argument although the POSIX standard does not require this.
 *      This is not longer true since at least POSIX.1-2008
 *  (2) The fields sa_handler and sa_sigaction may overlap, and a conforming
 *      application should not use both simultaneously.
 */

typedef void (*_sig_func_ptr)(int);

struct sigaction {
  int         sa_flags;       /* Special flags to affect behavior of signal */
  sigset_t    sa_mask;        /* Additional set of signals to be blocked */
                              /*   during execution of signal-catching */
                              /*   function. */
  union {
    _sig_func_ptr _handler;  /* SIG_DFL, SIG_IGN, or pointer to a function */
#if defined(_POSIX_REALTIME_SIGNALS)
    void      (*_sigaction)( int, siginfo_t *, void * );
#endif
  } _signal_handlers;
};

#define sa_handler    _signal_handlers._handler
#if defined(_POSIX_REALTIME_SIGNALS)
#define sa_sigaction  _signal_handlers._sigaction
#endif

#else /* defined(__rtems__) || defined(__ASYLO__) */

#define SA_NOCLDSTOP 1  /* only value supported now for sa_flags */

typedef void (*_sig_func_ptr)(int);

struct sigaction
{
	_sig_func_ptr sa_handler;
	sigset_t sa_mask;
	int sa_flags;
};
#endif /* defined(__rtems__) || defined(__ASYLO__) */
#endif /* defined(__CYGWIN__) */

#if __BSD_VISIBLE || __XSI_VISIBLE >= 4 || __POSIX_VISIBLE >= 200809
/*
 * Minimum and default signal stack constants. Allow for target overrides
 * from <sys/features.h>.
 */
#ifndef	MINSIGSTKSZ
#define	MINSIGSTKSZ	2048
#endif
#ifndef	SIGSTKSZ
#define	SIGSTKSZ	8192
#endif

/*
 * Possible values for ss_flags in stack_t below.
 */
#define	SS_ONSTACK	0x1
#define	SS_DISABLE	0x2

#endif

/*
 * Structure used in sigaltstack call.
 */
typedef struct sigaltstack {
  void     *ss_sp;    /* Stack base or pointer.  */
  int       ss_flags; /* Flags.  */
  size_t    ss_size;  /* Stack size.  */
} stack_t;

#if __POSIX_VISIBLE
#define SIG_SETMASK 0	/* set mask with sigprocmask() */
#define SIG_BLOCK 1	/* set of signals to block */
#define SIG_UNBLOCK 2	/* set of signals to, well, unblock */

int _EXFUN(sigprocmask, (int how, const sigset_t *set, sigset_t *oset));
#endif

#if __POSIX_VISIBLE >= 199506
int _EXFUN(pthread_sigmask, (int how, const sigset_t *set, sigset_t *oset));
#endif

#if defined(__CYGWIN__) || defined(__rtems__)
#ifdef _COMPILING_NEWLIB
int _EXFUN(_kill, (pid_t, int));
#endif /* _COMPILING_NEWLIB */
#endif /* __CYGWIN__ || __rtems__ */

#if __POSIX_VISIBLE
int _EXFUN(kill, (pid_t, int));
#endif

#if __BSD_VISIBLE || __XSI_VISIBLE >= 4
int _EXFUN(killpg, (pid_t, int));
#endif
#if __POSIX_VISIBLE
int _EXFUN(sigaction, (int, const struct sigaction *, struct sigaction *));
int _EXFUN(sigaddset, (sigset_t *, const int));
int _EXFUN(sigdelset, (sigset_t *, const int));
int _EXFUN(sigismember, (const sigset_t *, int));
int _EXFUN(sigfillset, (sigset_t *));
int _EXFUN(sigemptyset, (sigset_t *));
int _EXFUN(sigpending, (sigset_t *));
int _EXFUN(sigsuspend, (const sigset_t *));
int _EXFUN(sigwait, (const sigset_t *set, int *sig));

#if !defined(__CYGWIN__) && !defined(__rtems__)
/* These depend upon the type of sigset_t, which right now 
   is always a long.. They're in the POSIX namespace, but
   are not ANSI. */
#define sigaddset(what,sig) (*(what) |= (1<<(sig)), 0)
#define sigdelset(what,sig) (*(what) &= ~(1<<(sig)), 0)
#define sigemptyset(what)   (*(what) = 0, 0)
#define sigfillset(what)    (*(what) = ~(0), 0)
#define sigismember(what,sig) (((*(what)) & (1<<(sig))) != 0)
#endif /* !__CYGWIN__ && !__rtems__ */
#endif /* __POSIX_VISIBLE */

/* There are two common sigpause variants, both of which take an int argument.
   If you request _XOPEN_SOURCE or _GNU_SOURCE, you get the System V version,
   which removes the given signal from the process's signal mask; otherwise
   you get the BSD version, which sets the process's signal mask to the given
   value. */
#if __XSI_VISIBLE && !defined(__INSIDE_CYGWIN__)
# ifdef __GNUC__
int _EXFUN(sigpause, (int)) __asm__ (__ASMNAME ("__xpg_sigpause"));
# else
int _EXFUN(__xpg_sigpause, (int));
#  define sigpause __xpg_sigpause
# endif
#elif __BSD_VISIBLE
int _EXFUN(sigpause, (int));
#endif

#if __BSD_VISIBLE || __XSI_VISIBLE >= 4 || __POSIX_VISIBLE >= 200809
int _EXFUN(sigaltstack, (const stack_t *__restrict, stack_t *__restrict));
#endif

#if __POSIX_VISIBLE >= 199506
int _EXFUN(pthread_kill, (pthread_t thread, int sig));
#endif

#if __POSIX_VISIBLE >= 199309

/*  3.3.8 Synchronously Accept a Signal, P1003.1b-1993, p. 76
    NOTE: P1003.1c/D10, p. 39 adds sigwait().  */

int _EXFUN(sigwaitinfo, (const sigset_t *set, siginfo_t *info));
int _EXFUN(sigtimedwait,
  (const sigset_t *set, siginfo_t *info, const struct timespec  *timeout)
);
/*  3.3.9 Queue a Signal to a Process, P1003.1b-1993, p. 78 */
int _EXFUN(sigqueue, (pid_t pid, int signo, const union sigval value));

#endif /* __POSIX_VISIBLE >= 199309 */

#if defined(___AM29K__)
/* These all need to be defined for ANSI C, but I don't think they are
   meaningful.  */
#define SIGABRT 1
#define SIGFPE 1
#define SIGILL 1
#define SIGINT 1
#define SIGSEGV 1
#define SIGTERM 1
/* These need to be defined for POSIX, and some others do too.  */
#define SIGHUP 1
#define SIGQUIT 1
#define NSIG 2
#elif defined(__GO32__)
#define SIGINT  1
#define SIGKILL 2
#define SIGPIPE 3
#define SIGFPE  4
#define SIGHUP  5
#define SIGTERM 6
#define SIGSEGV 7
#define SIGTSTP 8
#define SIGQUIT 9
#define SIGTRAP 10
#define SIGILL  11
#define SIGEMT  12
#define SIGALRM 13
#define SIGBUS  14
#define SIGLOST 15
#define SIGSTOP 16
#define SIGABRT 17
#define SIGUSR1	18
#define SIGUSR2	19
#define NSIG    20
#elif !defined(SIGTRAP)
#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt */
#define	SIGQUIT	3	/* quit */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGIOT	6	/* IOT instruction */
#define	SIGABRT 6	/* used by abort, replace SIGIOT in the future */
#define	SIGEMT	7	/* EMT instruction */
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGSEGV	11	/* segmentation violation */
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */

#if defined(__rtems__)
#define	SIGURG	16	/* urgent condition on IO channel */
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGCLD	20	/* System V name for SIGCHLD */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	SIGIO	23	/* input/output possible signal */
#define	SIGPOLL	SIGIO	/* System V name for SIGIO */
#define	SIGWINCH 24	/* window changed */
#define	SIGUSR1 25	/* user defined signal 1 */
#define	SIGUSR2 26	/* user defined signal 2 */

/* Real-Time Signals Range, P1003.1b-1993, p. 61
   NOTE: By P1003.1b-1993, this should be at least RTSIG_MAX
         (which is a minimum of 8) signals.
 */
#define SIGRTMIN 27
#define SIGRTMAX 31
#define __SIGFIRSTNOTRT SIGHUP
#define __SIGLASTNOTRT  SIGUSR2

#define NSIG	32      /* signal 0 implied */

#elif defined(__svr4__)
/* svr4 specifics. different signals above 15, and sigaction. */
#define	SIGUSR1	16
#define SIGUSR2	17
#define SIGCLD	18
#define	SIGPWR	19
#define SIGWINCH 20
#define	SIGPOLL	22	/* 20 for x.out binaries!!!! */
#define	SIGSTOP	23	/* sendable stop signal not from tty */
#define	SIGTSTP	24	/* stop signal from tty */
#define	SIGCONT	25	/* continue a stopped process */
#define	SIGTTIN	26	/* to readers pgrp upon background tty read */
#define	SIGTTOU	27	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define NSIG	28	
#else
#define	SIGURG	16	/* urgent condition on IO channel */
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGCLD	20	/* System V name for SIGCHLD */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	SIGIO	23	/* input/output possible signal */
#define	SIGPOLL	SIGIO	/* System V name for SIGIO */
#define	SIGXCPU	24	/* exceeded CPU time limit */
#define	SIGXFSZ	25	/* exceeded file size limit */
#define	SIGVTALRM 26	/* virtual time alarm */
#define	SIGPROF	27	/* profiling time alarm */
#define	SIGWINCH 28	/* window changed */
#define	SIGLOST 29	/* resource lost (eg, record-lock lost) */
#define	SIGUSR1 30	/* user defined signal 1 */
#define	SIGUSR2 31	/* user defined signal 2 */
#define NSIG	32      /* signal 0 implied */
#endif
#endif

/* Some software assumes and directly uses an internal _NSIG macro. */
#define _NSIG NSIG

#define POLL_IN 1
#define POLL_OUT 2
#define POLL_MSG 3
#define POLL_ERR 4
#define POLL_PRI 5
#define POLL_HUP 6

/* sigevent definitions */
#define SIGEV_SIGNAL 0	/* notify via signal */
#define SIGEV_NONE 1	/* other notification: meaningless */
#define SIGEV_THREAD 2	/* deliver via thread creation */
#define SIGEV_THREAD_ID 4	/* deliver to thread */

#ifdef __cplusplus
}
#endif

#if defined(__CYGWIN__)
#if __XSI_VISIBLE >= 4 || __POSIX_VISIBLE >= 200809
#include <sys/ucontext.h>
#endif
#endif

#ifndef _SIGNAL_H_
/* Some applications take advantage of the fact that <sys/signal.h>
 * and <signal.h> are equivalent in glibc.  Allow for that here.  */
#include <signal.h>
#endif
#endif /* _SYS_SIGNAL_H */
