/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <unistd.h> (POSIX), the file and process calls. */
#ifndef _UNISTD_H
#define _UNISTD_H
#include <sys/types.h>
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
extern char **environ;
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int close(int fd);
off_t lseek(int fd, off_t offset, int whence);
int pipe(int fds[2]);
int dup(int fd);
int dup2(int from, int to);
int unlink(const char *path);
int rmdir(const char *path);
int link(const char *target, const char *name);
int symlink(const char *target, const char *name);
ssize_t readlink(const char *path, char *buf, size_t n);
int chdir(const char *path);
char *getcwd(char *buf, size_t n);
int access(const char *path, int mode);
int isatty(int fd);
int ftruncate(int fd, off_t length);
int truncate(const char *path, off_t length);
int fsync(int fd);
pid_t fork(void);
int execve(const char *path, char *const argv[], char *const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
_Noreturn void _exit(int status);
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
pid_t setsid(void);
int setpgid(pid_t pid, pid_t pgid);
pid_t getpgrp(void);
unsigned sleep(unsigned seconds);
int usleep(unsigned long usec);
int gethostname(char *name, size_t n);
#endif
