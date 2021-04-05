#ifndef _SYS_IOCTL_H_
#define _SYS_IOCTL_H_

#include <stdint.h>
#include <sys/ioccom.h>  // IWYU pragma: export

#define TIOCGWINSZ 0x5413

struct winsize {
  uint16_t ws_row;
  uint16_t ws_col;
  uint16_t ws_xpixel;
  uint16_t ws_ypixel;
};

#ifdef __cplusplus
extern "C" {
#endif

int ioctl(int fd, int request, ...);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* _SYS_IOCTL_H_ */
