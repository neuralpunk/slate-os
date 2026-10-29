// SPDX-License-Identifier: MIT OR Apache-2.0
// A native app from quarry (ADR 0130), built with tools/slate-cc and
// installed as qapp (permissions: network) and qbare (permissions: none).
// Unsigned by any key the kernel trusts, it runs in the Slate domain only
// because quarry's registry lists it, confined to what it declared. It
// says what it is allowed: an internet socket, a file of root's (the
// users' files), the GPU's device node, and whether a program it runs (a
// system one, unconfined on its own) is still held back.
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/// The value of `key` in /proc/self/status, into `out`.
static void status(const char *key, char *out, size_t len) {
    snprintf(out, len, "?");
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    size_t k = strlen(key);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, k) == 0 && line[k] == ':') {
            char *v = line + k + 1;
            while (*v == ' ' || *v == '\t') v++;
            v[strcspn(v, "\n")] = 0;
            snprintf(out, len, "%s", v);
        }
    }
    fclose(f);
}

static const char *opens(const char *path, int flags) {
    int fd = open(path, flags);
    if (fd >= 0) {
        close(fd);
        return "ok";
    }
    return errno == EACCES ? "denied" : "error";
}

int main(void) {
    char domain[32], perms[128];
    status("Domain", domain, sizeof domain);
    status("Permissions", perms, sizeof perms);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    const char *inet = s >= 0 ? "ok" : errno == EACCES ? "denied" : "error";
    if (s >= 0) close(s);
    const char *home = opens("/root/qsecret", O_RDONLY);
    const char *gpu = opens("/dev/dri/card0", O_RDWR);
    // A system program run from here keeps the app's limits.
    const char *child = "error";
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        dup2(null, 2);
        dup2(null, 1);
        char *argv[] = {"cat", "/root/qsecret", 0};
        execv("/bin/cat", argv);
        _exit(127);
    }
    int st = 0;
    if (pid > 0 && waitpid(pid, &st, 0) == pid) child = WIFEXITED(st) && WEXITSTATUS(st) == 0 ? "ok" : "denied";
    printf("domain=%s permissions=%s inet=%s home=%s gpu=%s child-home=%s\n", domain, perms, inet, home, gpu, child);
    return 0;
}
