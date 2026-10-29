// SPDX-License-Identifier: MIT OR Apache-2.0
// memfd seals against writable shared mappings (memfd_create(2):
// F_SEAL_WRITE is EBUSY while one exists, and none can be made after),
// pidfd_send_signal(2)'s siginfo, and membarrier(2)'s global command.
// Runs on the host too.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::memfd::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static volatile int got_code, got_pid, got_value;

static void on_usr1(int s, siginfo_t *si, void *ctx) {
    (void)s, (void)ctx;
    got_code = si->si_code;
    got_pid = si->si_pid;
    got_value = si->si_value.sival_int;
}

static int send(int pidfd, int sig, siginfo_t *info) {
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, 0);
}

int main(void) {
    int fd = memfd_create("sealed", MFD_ALLOW_SEALING);
    ftruncate(fd, 4096);
    char *w = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    errno = 0;
    check("seal_write_busy", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EBUSY);
    check("seal_not_added", fcntl(fd, F_GET_SEALS) == 0);
    munmap(w, 4096);
    check("seal_write", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    errno = 0;
    check("map_writable_refused", mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EPERM);
    char *r = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    check("map_read_only", r != MAP_FAILED);
    errno = 0;
    check("mprotect_refused", mprotect(r, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    char *priv = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check("map_private", priv != MAP_FAILED && (priv[0] = 1));
    close(fd);

    // F_SEAL_FUTURE_WRITE keeps the mappings there are.
    fd = memfd_create("future", MFD_ALLOW_SEALING);
    ftruncate(fd, 4096);
    w = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("future_write_with_mapping", fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0);
    w[0] = 'x';
    char c = 0;
    pread(fd, &c, 1, 0);
    check("future_write_old_mapping_writes", c == 'x');
    errno = 0;
    check("future_write_new_mapping_refused",
          mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EPERM);
    close(fd);

    struct sigaction sa = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, 0);
    int me = syscall(SYS_pidfd_open, getpid(), 0);
    check("pidfd_kill_info", send(me, SIGUSR1, 0) == 0 && got_code == SI_USER && got_pid == getpid());
    siginfo_t info;
    memset(&info, 0, sizeof info);
    info.si_signo = SIGUSR1;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();
    info.si_value.sival_int = 42;
    check("pidfd_queued_info", send(me, SIGUSR1, &info) == 0 && got_code == SI_QUEUE && got_value == 42);
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    int other = syscall(SYS_pidfd_open, child, 0);
    info.si_code = SI_KERNEL;
    errno = 0;
    check("pidfd_kernel_code_refused", send(other, SIGUSR1, &info) == -1 && errno == EPERM);
    send(other, SIGKILL, 0);
    waitpid(child, 0, 0);

    long cmds = syscall(SYS_membarrier, 0, 0, 0);
    check("membarrier_global", cmds > 0 && (cmds & 1) && syscall(SYS_membarrier, 1, 0, 0) == 0);
    return failures != 0;
}
