// SPDX-License-Identifier: MIT OR Apache-2.0
// Send MIB mebibytes of a pattern (byte i is i mod 251) to HOST:PORT over
// TCP, in 64 KiB writes, then print "netsend: N bytes in S s (R MB/s)".
// The NIC scenario's host sink checks every byte (phase 6: segmentation
// offload must not change the stream).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: netsend HOST PORT MIB\n");
        return 2;
    }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
    if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) return 2;
    long total = atol(argv[3]) << 20;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        perror("netsend: connect");
        return 1;
    }
    // The pattern, one period longer than a write: writing from offset
    // (bytes sent mod 251) continues the stream.
    enum { CHUNK = 64 * 1024 };
    static unsigned char buf[CHUNK + 251];
    for (unsigned i = 0; i < sizeof buf; i++) buf[i] = i % 251;
    double t0 = now();
    long sent = 0;
    while (sent < total) {
        long want = total - sent < CHUNK ? total - sent : CHUNK;
        ssize_t n = write(s, buf + sent % 251, want);
        if (n <= 0) {
            perror("netsend: write");
            return 1;
        }
        sent += n;
    }
    shutdown(s, SHUT_WR);
    char c;
    while (read(s, &c, 1) > 0) {
    }
    double dt = now() - t0;
    printf("netsend: %ld bytes in %.2f s (%.0f MB/s)\n", sent, dt, sent / dt / 1e6);
    close(s);
    return 0;
}
