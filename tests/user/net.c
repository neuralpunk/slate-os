// SPDX-License-Identifier: MIT OR Apache-2.0
// UDP and ICMP sockets: loopback, then the network QEMU provides (DHCP
// address, the host at 10.0.2.2 running xtask's UDP echo server).
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::net::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static struct sockaddr_in addr(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static long ms_since(struct timespec a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
}

static int echo_port(void) {
    char buf[512] = {0};
    int fd = open("/proc/cmdline", O_RDONLY);
    read(fd, buf, sizeof buf - 1);
    close(fd);
    char *p = strstr(buf, "slate.echo=");
    return p ? atoi(p + 11) : 0;
}

int main(void) {
    // Loopback.
    int rx = socket(AF_INET, SOCK_DGRAM, 0), tx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in lo = addr("127.0.0.1", 0), got;
    socklen_t len = sizeof got;
    check("bind", bind(rx, (struct sockaddr *)&lo, sizeof lo) == 0 &&
                      getsockname(rx, (struct sockaddr *)&got, &len) == 0 && ntohs(got.sin_port) >= 49152);
    check("sendto", sendto(tx, "hello", 5, 0, (struct sockaddr *)&got, sizeof got) == 5);
    struct pollfd pfd = {.fd = rx, .events = POLLIN};
    check("poll_readable", poll(&pfd, 1, 1000) == 1 && (pfd.revents & POLLIN));
    int avail = 0;
    check("fionread", ioctl(rx, FIONREAD, &avail) == 0 && avail == 5);
    char buf[2048];
    check("peek", recv(rx, buf, sizeof buf, MSG_PEEK) == 5);
    struct sockaddr_in from;
    len = sizeof from;
    int n = recvfrom(rx, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
    check("recvfrom", n == 5 && memcmp(buf, "hello", 5) == 0 && from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    check("nonblock_empty", recv(rx, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct timeval tv = {0, 100000};
    setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = recv(rx, buf, sizeof buf, 0);
    long waited = ms_since(t0);
    check("rcvtimeo", r == -1 && errno == EAGAIN && waited >= 90 && waited < 1000);
    // Connected sockets, send/recv, truncation, and refused ports.
    check("connect", connect(tx, (struct sockaddr *)&got, sizeof got) == 0 && send(tx, "0123456789", 10, 0) == 10);
    check("truncated", recv(rx, buf, 4, 0) == 4 && memcmp(buf, "0123", 4) == 0 &&
                           recv(rx, buf, sizeof buf, MSG_DONTWAIT) == -1);
    int lone = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in closed = addr("127.0.0.1", 9);
    connect(lone, (struct sockaddr *)&closed, sizeof closed);
    send(lone, "x", 1, 0);
    usleep(10000);
    check("refused", recv(lone, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == ECONNREFUSED);

    // The network: wait for DHCP (the address shows on eth0).
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "eth0");
    int configured = 0;
    for (int i = 0; i < 500 && !configured; i++) {
        configured = ioctl(rx, SIOCGIFADDR, &ifr) == 0;
        if (!configured) usleep(10000);
    }
    struct sockaddr_in *me = (struct sockaddr_in *)&ifr.ifr_addr;
    check("dhcp_address", configured && me->sin_addr.s_addr == inet_addr("10.0.2.15"));
    char pnp[256] = {0};
    int pf = open("/proc/net/pnp", O_RDONLY);
    read(pf, pnp, sizeof pnp - 1);
    close(pf);
    check("dhcp_nameserver", strstr(pnp, "nameserver 10.0.2.3") != NULL);
    struct ifreq hw = {0};
    strcpy(hw.ifr_name, "eth0");
    check("hwaddr", ioctl(rx, SIOCGIFHWADDR, &hw) == 0 && (unsigned char)hw.ifr_hwaddr.sa_data[0] == 0x52);

    // UDP to the host's echo server, through ARP and the gateway.
    int port = echo_port();
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in host = addr("10.0.2.2", port);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int echoed = 0;
    for (int i = 0; i < 3 && !echoed; i++) {
        sendto(u, "echo me", 7, 0, (struct sockaddr *)&host, sizeof host);
        len = sizeof from;
        n = recvfrom(u, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
        echoed = n == 7 && memcmp(buf, "echo me", 7) == 0 && from.sin_port == htons(port);
    }
    check("udp_echo_host", port != 0 && echoed);
    // A bigger datagram, near the MTU.
    char big[1400];
    for (int i = 0; i < (int)sizeof big; i++) big[i] = i * 7;
    sendto(u, big, sizeof big, 0, (struct sockaddr *)&host, sizeof host);
    n = recv(u, buf, sizeof buf, 0);
    check("udp_echo_big", n == (int)sizeof big && memcmp(buf, big, sizeof big) == 0);

    // Ping the gateway with a ping socket.
    int ping = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    struct icmphdr echo = {.type = ICMP_ECHO, .un.echo.sequence = htons(1)};
    struct sockaddr_in gw = addr("10.0.2.2", 0);
    setsockopt(ping, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int pinged = sendto(ping, &echo, sizeof echo, 0, (struct sockaddr *)&gw, sizeof gw) == sizeof echo;
    n = recv(ping, buf, sizeof buf, 0);
    check("ping_gateway", pinged && n >= 8 && ((struct icmphdr *)buf)->type == ICMP_ECHOREPLY);
    close(ping);

    // Who may open ping and raw sockets (icmp(7), raw(7); ADR 0052): ping
    // sockets for the groups in ping_group_range (all by default), raw
    // ones only with CAP_NET_RAW.
    char range[64] = {0};
    int rf = open("/proc/sys/net/ipv4/ping_group_range", O_RDONLY);
    read(rf, range, sizeof range - 1);
    close(rf);
    check("ping_groups_default", strcmp(range, "0\t2147483647\n") == 0);
    rf = open("/proc/sys/net/ipv4/ping_group_range", O_WRONLY);
    write(rf, "1 0", 3);
    close(rf);
    errno = 0;
    check("ping_groups_enforced", socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) == -1 && errno == EACCES &&
                                      socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) == -1 && errno == EACCES);
    rf = open("/proc/sys/net/ipv4/ping_group_range", O_WRONLY);
    write(rf, range, strlen(range));
    close(rf);
    int pipefd[2];
    pipe(pipefd);
    if (fork() == 0) {
        setgroups(0, NULL);
        setgid(65534);
        setuid(65534);
        int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        char ok = p >= 0 && raw == -1 && errno == EPERM;
        write(pipefd[1], &ok, 1);
        _exit(0);
    }
    char ok = 0;
    read(pipefd[0], &ok, 1);
    wait(NULL);
    check("ping_unprivileged", ok);
    return failures != 0;
}
