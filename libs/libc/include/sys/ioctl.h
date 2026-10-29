/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0075): <sys/ioctl.h>: ioctl(2) and the terminal
 * requests (ioctl_tty(2); Linux's numbers, which Slate shares). */
#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H
struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TIOCSCTTY 0x540E
#define TIOCGPGRP 0x540F
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define FIONREAD 0x541B
#define FIONBIO 0x5421
int ioctl(int fd, unsigned long request, ...);
#endif
