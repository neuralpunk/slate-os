// SPDX-License-Identifier: MIT OR Apache-2.0
// AF_UNIX sockets (socketpair, named and abstract addresses, descriptor
// passing, credentials), netlink route dumps through getifaddrs(3) and
// netlink uevent sockets (multicast between sockets, SCM_CREDENTIALS,
// socket filters).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

// Classic BPF socket filters (socket(7), bpf(4)); numbers from musl's
// sys/socket.h.
struct sock_filter { unsigned short code; unsigned char jt, jf; unsigned k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };
#ifndef SO_LOCK_FILTER
#define SO_LOCK_FILTER 44
#endif

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::unix::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static int send_fd(int sock, int fd) {
    char byte = 'F';
    struct iovec iov = {&byte, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.buf, .msg_controllen = sizeof u.buf};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    return sendmsg(sock, &m, 0);
}

static int recv_fd(int sock) {
    char byte;
    struct iovec iov = {&byte, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.buf, .msg_controllen = sizeof u.buf};
    if (recvmsg(sock, &m, 0) != 1 || byte != 'F') return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof fd);
    return fd;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    // socketpair: both directions, EOF, EPIPE.
    int sv[2];
    char b[256];
    check("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    check("pair_io", write(sv[0], "ping", 4) == 4 && read(sv[1], b, sizeof b) == 4 && memcmp(b, "ping", 4) == 0 &&
                         write(sv[1], "pong", 4) == 4 && read(sv[0], b, sizeof b) == 4);
    struct pollfd pfd = {.fd = sv[1], .events = POLLIN};
    check("pair_poll_empty", poll(&pfd, 1, 0) == 0);
    close(sv[0]);
    check("pair_eof", read(sv[1], b, sizeof b) == 0);
    check("pair_epipe", write(sv[1], "x", 1) == -1 && errno == EPIPE);
    close(sv[1]);

    // A named listening socket and a client in a child process.
    const char *path = "/tmp/slate-test.sock";
    unlink(path);
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, path);
    struct stat st;
    check("bind_path", bind(l, (struct sockaddr *)&a, sizeof a) == 0 && stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
    check("bind_busy", bind(socket(AF_UNIX, SOCK_STREAM, 0), (struct sockaddr *)&a, sizeof a) == -1 && errno == EADDRINUSE);
    listen(l, 4);
    pid_t child = fork();
    if (child == 0) {
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&a, sizeof a) != 0) _exit(1);
        write(c, "from child", 10);
        int n = read(c, b, sizeof b);
        _exit(n == 6 && memcmp(b, "parent", 6) == 0 ? 0 : 2);
    }
    int s = accept(l, NULL, NULL);
    int n = read(s, b, sizeof b);
    check("accept_read", s >= 0 && n == 10 && memcmp(b, "from child", 10) == 0);
    struct ucred cred;
    socklen_t clen = sizeof cred;
    check("peercred", getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0 && cred.pid == child);
    struct sockaddr_un name;
    socklen_t nlen = sizeof name;
    check("getsockname", getsockname(s, (struct sockaddr *)&name, &nlen) == 0 && strcmp(name.sun_path, path) == 0);
    write(s, "parent", 6);
    int status;
    waitpid(child, &status, 0);
    check("child_ok", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(s);
    // The socket reached through bind mounts, as bubblewrap gives a
    // sandbox the D-Bus socket: the file bound over another, and its
    // directory bound elsewhere.
    int bmok = 0, bdok = 0;
    close(open("/tmp/slate-bound.sock", O_CREAT | O_WRONLY, 0644));
    if (mount(path, "/tmp/slate-bound.sock", NULL, MS_BIND, NULL) == 0) {
        struct sockaddr_un via = {.sun_family = AF_UNIX};
        strcpy(via.sun_path, "/tmp/slate-bound.sock");
        int c1 = socket(AF_UNIX, SOCK_STREAM, 0);
        int r = connect(c1, (struct sockaddr *)&via, sizeof via);
        int s1 = r == 0 ? accept(l, NULL, NULL) : -1;
        bmok = r == 0 && s1 >= 0;
        if (!bmok) printf("bound file: connect %d errno %d\n", r, errno);
        close(c1);
        close(s1);
        umount("/tmp/slate-bound.sock");
    }
    unlink("/tmp/slate-bound.sock");
    mkdir("/tmp/slate-bound-dir", 0755);
    if (mount("/tmp", "/tmp/slate-bound-dir", NULL, MS_BIND, NULL) == 0) {
        struct sockaddr_un via = {.sun_family = AF_UNIX};
        strcpy(via.sun_path, "/tmp/slate-bound-dir/slate-test.sock");
        int c1 = socket(AF_UNIX, SOCK_STREAM, 0);
        int r = connect(c1, (struct sockaddr *)&via, sizeof via);
        int s1 = r == 0 ? accept(l, NULL, NULL) : -1;
        bdok = r == 0 && s1 >= 0;
        if (!bdok) printf("bound dir: connect %d errno %d\n", r, errno);
        close(c1);
        close(s1);
        umount("/tmp/slate-bound-dir");
    }
    rmdir("/tmp/slate-bound-dir");
    check("connect_bound_file", bmok);
    check("connect_bound_dir", bdok);
    close(l);
    struct sockaddr_un gone = {.sun_family = AF_UNIX};
    strcpy(gone.sun_path, "/tmp/nobody-listens");
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    check("connect_missing", connect(c, (struct sockaddr *)&gone, sizeof gone) == -1 && errno == ENOENT);
    close(c);
    unlink(path);

    // Passing a pipe's write end to another process.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int pipefd[2];
    pipe(pipefd);
    child = fork();
    if (child == 0) {
        close(sv[0]);
        int fd = recv_fd(sv[1]);
        if (fd < 0) _exit(1);
        write(fd, "via passed fd", 13);
        _exit(0);
    }
    close(sv[1]);
    check("send_fd", send_fd(sv[0], pipefd[1]) == 1);
    close(pipefd[1]);
    n = read(pipefd[0], b, sizeof b);
    waitpid(child, &status, 0);
    check("scm_rights", n == 13 && memcmp(b, "via passed fd", 13) == 0 && WEXITSTATUS(status) == 0);
    close(sv[0]);
    close(pipefd[0]);

    // Datagrams: abstract names, boundaries and sender addresses.
    int d1 = socket(AF_UNIX, SOCK_DGRAM, 0), d2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un a1 = {.sun_family = AF_UNIX}, a2 = {.sun_family = AF_UNIX};
    memcpy(a1.sun_path, "\0slate-d1", 9);
    memcpy(a2.sun_path, "\0slate-d2", 9);
    socklen_t al = offsetof(struct sockaddr_un, sun_path) + 9;
    bind(d1, (struct sockaddr *)&a1, al);
    bind(d2, (struct sockaddr *)&a2, al);
    sendto(d1, "one", 3, 0, (struct sockaddr *)&a2, al);
    sendto(d1, "second", 6, 0, (struct sockaddr *)&a2, al);
    struct sockaddr_un from;
    socklen_t fl = sizeof from;
    int n1 = recvfrom(d2, b, sizeof b, 0, (struct sockaddr *)&from, &fl);
    int n2 = recv(d2, b, sizeof b, 0);
    check("dgram", n1 == 3 && n2 == 6 && fl == al && memcmp(from.sun_path, "\0slate-d1", 9) == 0);
    close(d1);
    close(d2);

    // Netlink: getifaddrs and if_nametoindex.
    struct ifaddrs *ifs;
    int saw_lo = 0, saw_eth = 0;
    if (getifaddrs(&ifs) == 0) {
        for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)i->ifa_addr;
            if (!strcmp(i->ifa_name, "lo") && sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) saw_lo = 1;
            if (!strcmp(i->ifa_name, "eth0") && sin->sin_addr.s_addr == inet_addr("10.0.2.15")) saw_eth = 1;
        }
        freeifaddrs(ifs);
    }
    check("getifaddrs", saw_lo && saw_eth);
    check("if_nametoindex", if_nametoindex("eth0") == 2 && if_nametoindex("lo") == 1);

    // A closed peer: readable, writable (EPIPE), hung up, no error
    // (observed Linux behaviour).
    int hp[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, hp);
    close(hp[1]);
    struct pollfd hpf = {hp[0], POLLIN | POLLOUT | POLLRDHUP, 0};
    poll(&hpf, 1, 0);
    check("peer_closed_poll", (hpf.revents & (POLLIN | POLLOUT | POLLRDHUP | POLLHUP)) == (POLLIN | POLLOUT | POLLRDHUP | POLLHUP) &&
                                  !(hpf.revents & POLLERR));
    close(hp[0]);

    // Netlink uevent sockets (netlink(7)): AF_NETLINK 16, protocol
    // NETLINK_KOBJECT_UEVENT 15; sockaddr_nl is family, pad, port, groups.
    struct nl { unsigned short family, pad; unsigned port, groups; };
    int u1 = socket(16, SOCK_RAW | SOCK_CLOEXEC, 15);
    int u2 = socket(16, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 15);
    struct nl ua1 = {16, 0, 0, 1}, ua2 = {16, 0, 0, 1u << 3}, got = {0};
    socklen_t gl = sizeof got;
    check("uevent_bind", u1 >= 0 && u2 >= 0 && bind(u1, (struct sockaddr *)&ua1, sizeof ua1) == 0 &&
                             bind(u2, (struct sockaddr *)&ua2, sizeof ua2) == 0 &&
                             getsockname(u1, (struct sockaddr *)&got, &gl) == 0 && got.port == (unsigned)getpid() &&
                             got.groups == 1);
    check("uevent_empty", recv(u2, b, sizeof b, 0) < 0 && errno == EAGAIN);
    int on = 1;
    setsockopt(u2, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
    struct nl to = {16, 0, 0, 1u << 3};
    check("uevent_send", sendto(u1, "add@/x\0ACTION=add", 17, 0, (struct sockaddr *)&to, sizeof to) == 17);
    struct nl from_nl = {0};
    char cbuf[64];
    struct iovec iov = {b, sizeof b};
    struct msghdr mh = {.msg_name = &from_nl, .msg_namelen = sizeof from_nl, .msg_iov = &iov, .msg_iovlen = 1,
                        .msg_control = cbuf, .msg_controllen = sizeof cbuf};
    ssize_t un = recvmsg(u2, &mh, 0);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    struct ucred *uc = cm ? (struct ucred *)CMSG_DATA(cm) : NULL;
    check("uevent_multicast", un == 17 && memcmp(b, "add@/x", 7) == 0 && from_nl.port == got.port &&
                                  from_nl.groups == (1u << 3));
    check("uevent_credentials", cm && cm->cmsg_type == SCM_CREDENTIALS && uc->pid == getpid() && uc->uid == 0);

    // Socket filters (socket(7), bpf(4)): keep messages whose first byte is
    // 'k', and only their first four bytes; drop the rest. Opcodes: ld
    // byte at k (0x30), jeq k (0x15), ret k (0x06).
    struct sock_filter keep_k[] = {
        {0x30, 0, 0, 0},
        {0x15, 0, 1, 'k'},
        {0x06, 0, 0, 4},
        {0x06, 0, 0, 0},
    };
    struct sock_fprog prog = {4, keep_k};
    check("uevent_filter_attach", setsockopt(u2, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) == 0);
    sendto(u1, "drop me", 7, 0, (struct sockaddr *)&to, sizeof to);
    sendto(u1, "keep me", 7, 0, (struct sockaddr *)&to, sizeof to);
    ssize_t fn = recv(u2, b, sizeof b, 0);
    check("uevent_filtered", fn == 4 && memcmp(b, "keep", 4) == 0 && recv(u2, b, sizeof b, 0) < 0 && errno == EAGAIN);
    // A program jumping past its end is refused; detaching lets all through.
    struct sock_filter bad[] = {{0x05, 0, 0, 7}};
    struct sock_fprog badprog = {1, bad};
    check("uevent_filter_checked", setsockopt(u2, SOL_SOCKET, SO_ATTACH_FILTER, &badprog, sizeof badprog) < 0 && errno == EINVAL);
    check("uevent_filter_detach", setsockopt(u2, SOL_SOCKET, SO_DETACH_FILTER, &on, sizeof on) == 0);
    sendto(u1, "drop me", 7, 0, (struct sockaddr *)&to, sizeof to);
    check("uevent_unfiltered", recv(u2, b, sizeof b, 0) == 7);
    // Locked, the filter stays as it is (SO_LOCK_FILTER).
    int lk = 0;
    socklen_t lkl = sizeof lk;
    check("uevent_filter_lock", setsockopt(u2, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) == 0 &&
                                    setsockopt(u2, SOL_SOCKET, SO_LOCK_FILTER, &on, sizeof on) == 0 &&
                                    setsockopt(u2, SOL_SOCKET, SO_DETACH_FILTER, &on, sizeof on) < 0 && errno == EPERM &&
                                    getsockopt(u2, SOL_SOCKET, SO_LOCK_FILTER, &lk, &lkl) == 0 && lk == 1);
    close(u1);
    close(u2);

    // SO_PASSCRED on Unix sockets (unix(7)): each message comes with its
    // sender's credentials; without it, none. Firefox's IPC needs it.
    int cp[2];
    int pon = 1, pgot = 0;
    socklen_t pl = sizeof pgot;
    check("passcred_set", socketpair(AF_UNIX, SOCK_DGRAM, 0, cp) == 0 &&
                              setsockopt(cp[1], SOL_SOCKET, SO_PASSCRED, &pon, sizeof pon) == 0 &&
                              getsockopt(cp[1], SOL_SOCKET, SO_PASSCRED, &pgot, &pl) == 0 && pgot == 1);
    check("passcred_send", write(cp[0], "who", 3) == 3 && write(cp[1], "me", 2) == 2);
    char pc[64];
    struct iovec piov = {b, sizeof b};
    struct msghdr pm = {.msg_iov = &piov, .msg_iovlen = 1, .msg_control = pc, .msg_controllen = sizeof pc};
    ssize_t pn = recvmsg(cp[1], &pm, 0);
    struct cmsghdr *pcm = CMSG_FIRSTHDR(&pm);
    struct ucred *puc = pcm ? (struct ucred *)CMSG_DATA(pcm) : NULL;
    check("passcred_credentials", pn == 3 && pcm && pcm->cmsg_level == SOL_SOCKET && pcm->cmsg_type == SCM_CREDENTIALS &&
                                      puc->pid == getpid() && puc->uid == getuid() && puc->gid == getgid());
    struct msghdr pm2 = {.msg_iov = &piov, .msg_iovlen = 1, .msg_control = pc, .msg_controllen = sizeof pc};
    check("passcred_off_none", recvmsg(cp[0], &pm2, 0) == 2 && pm2.msg_controllen == 0);
    // As on Linux (observed), SO_REUSEPORT isn't for Unix sockets.
    check("reuseport_unix", setsockopt(cp[0], SOL_SOCKET, SO_REUSEPORT, &pon, sizeof pon) == -1 && errno == EOPNOTSUPP);
    close(cp[0]);
    close(cp[1]);
    return failures != 0;
}
