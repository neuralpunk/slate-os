// SPDX-License-Identifier: MIT OR Apache-2.0
//
// slate-libc (ADR 0031), checked from C: built by tools/slate-cc, run on
// Slate (native calls) and on the Linux host (cargo xtask check). Prints
// one line per check and exits with the number of failures. Files go
// under /tmp/nlibc-PID.

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("native-libc: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok)
        failures++;
}

static int by_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

static volatile sig_atomic_t got;
static void on_signal(int sig) { got = sig; }

static int exit_hook_ran;
static void at_exit_hook(void) { exit_hook_ran = 1; }

static void strings(void) {
    char buf[64];
    check("snprintf", snprintf(buf, sizeof buf, "%d|%5s|%-3x|%c|%%|%lu", -12, "ab", 255, 'z', 4000000000UL) == 28 &&
                          strcmp(buf, "-12|   ab|ff |z|%|4000000000") == 0);
    // Through a volatile pointer, so the compiler does not warn about the
    // truncation this checks.
    const char *volatile six = "abcdef";
    check("snprintf_truncates", snprintf(buf, 4, "%s", six) == 6 && strcmp(buf, "abc") == 0);
    check("sprintf_pointer", sprintf(buf, "%p", (void *)0x1234) == 6 && strcmp(buf, "0x1234") == 0);
    check("strlen_strcpy", strlen(strcpy(buf, "slate")) == 5);
    check("strcat", strcmp(strcat(buf, "-os"), "slate-os") == 0);
    check("strchr_strrchr", strchr(buf, '-') == buf + 5 && strrchr("a/b/c", '/')[1] == 'c');
    check("strstr", strstr("hello world", "o w") != NULL && strstr("abc", "x") == NULL);
    check("strncmp_strcasecmp", strncmp("abcd", "abce", 3) == 0 && strcasecmp("SLATE", "slate") == 0);
    char *d = strdup("copy");
    check("strdup", d && strcmp(d, "copy") == 0);
    free(d);
    char toks[] = "a,b,,c";
    char *t1 = strtok(toks, ","), *t2 = strtok(NULL, ","), *t3 = strtok(NULL, ",");
    check("strtok", t1 && t2 && t3 && !strcmp(t1, "a") && !strcmp(t2, "b") && !strcmp(t3, "c") && !strtok(NULL, ","));
    check("memcmp_memset", memcmp(memset(buf, 'x', 3), "xxx", 3) == 0);
    check("ctype", isalpha('q') && isdigit('7') && isspace('\t') && !isalnum('-') && toupper('a') == 'A');
    char *end;
    check("strtol", strtol("  -0x1fZ", &end, 16) == -31 && *end == 'Z');
    check("strtoul_base0", strtoul("0755", NULL, 0) == 0755);
    errno = 0;
    check("strtol_range", strtol("999999999999999999999", NULL, 10) == LONG_MAX && errno == ERANGE);
    check("atoi", atoi("42abc") == 42);
    check("strerror", strcmp(strerror(ENOENT), "No such file or directory") == 0);
}

static void memory(void) {
    int *v = malloc(5 * sizeof(int));
    int src[5] = {9, -3, 7, 0, 4};
    memcpy(v, src, sizeof src);
    qsort(v, 5, sizeof(int), by_int);
    check("qsort", v[0] == -3 && v[1] == 0 && v[4] == 9);
    int key = 7;
    check("bsearch", bsearch(&key, v, 5, sizeof(int), by_int) == &v[3]);
    v = realloc(v, 1000 * sizeof(int));
    check("realloc_keeps", v && v[4] == 9);
    v[999] = 1;
    free(v);
    int *z = calloc(100, sizeof(int));
    int zero = 1;
    for (int i = 0; i < 100; i++)
        zero &= z[i] == 0;
    check("calloc", zero);
    free(z);
}

static void environment(void) {
    check("setenv", setenv("NLIBC", "one", 1) == 0 && strcmp(getenv("NLIBC"), "one") == 0);
    check("setenv_keep", setenv("NLIBC", "two", 0) == 0 && strcmp(getenv("NLIBC"), "one") == 0);
    check("unsetenv", unsetenv("NLIBC") == 0 && getenv("NLIBC") == NULL);
    check("setenv_bad", setenv("A=B", "x", 1) == -1 && errno == EINVAL);
}

static void files(const char *dir) {
    char path[128], line[64];
    check("mkdir", mkdir(dir, 0755) == 0);
    snprintf(path, sizeof path, "%s/f", dir);
    FILE *f = fopen(path, "w");
    check("fopen_write", f != NULL);
    fprintf(f, "first %d\n", 1);
    fputs("second\n", f);
    check("fclose", fclose(f) == 0);
    f = fopen(path, "r");
    check("fgets", fgets(line, sizeof line, f) && strcmp(line, "first 1\n") == 0);
    check("fgetc_ungetc", fgetc(f) == 's' && ungetc('S', f) == 'S' && fgetc(f) == 'S');
    check("ftell", ftell(f) == 9);
    check("fseek_fread", fseek(f, 6, SEEK_SET) == 0 && fread(line, 1, 3, f) == 3 && memcmp(line, "1\ns", 3) == 0);
    fseek(f, 0, SEEK_END);
    check("feof", fgetc(f) == EOF && feof(f));
    fclose(f);
    struct stat st;
    check("stat", stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 15);
    int fd = open(path, O_WRONLY | O_APPEND);
    check("open_append", fd >= 0 && write(fd, "x", 1) == 1 && fstat(fd, &st) == 0 && st.st_size == 16);
    close(fd);
    // flock: a second open of the file is kept out while the first holds it.
    int l1 = open(path, O_RDONLY), l2 = open(path, O_RDONLY);
    check("flock", flock(l1, LOCK_EX) == 0 && flock(l2, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK &&
                       flock(l1, LOCK_UN) == 0 && flock(l2, LOCK_SH | LOCK_NB) == 0);
    close(l1);
    close(l2);
    check("open_missing", open("/nonexistent/x", O_RDONLY) == -1 && errno == ENOENT);
    char path2[128];
    snprintf(path2, sizeof path2, "%s/g", dir);
    check("rename", rename(path, path2) == 0 && access(path, F_OK) == -1 && access(path2, R_OK) == 0);
    DIR *dp = opendir(dir);
    int saw_dot = 0, saw_g = 0;
    struct dirent *e;
    while ((e = readdir(dp)) != NULL) {
        saw_dot |= strcmp(e->d_name, ".") == 0;
        saw_g |= strcmp(e->d_name, "g") == 0 && e->d_type == DT_REG;
    }
    closedir(dp);
    check("readdir", saw_dot && saw_g);
    char cwd[PATH_MAX];
    check("chdir_getcwd", chdir(dir) == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, dir) == 0);
    check("relative_open", (fd = open("g", O_RDONLY)) >= 0 && close(fd) == 0);
    chdir("/");
    check("remove", remove(path2) == 0 && rmdir(dir) == 0);
}

static void processes(void) {
    int fds[2];
    check("pipe", pipe(fds) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        execlp("echo", "echo", "from", "echo", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    char buf[32] = {0};
    ssize_t n = read(fds[0], buf, sizeof buf - 1);
    close(fds[0]);
    int status;
    check("fork_exec_pipe", waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                                n == 10 && strcmp(buf, "from echo\n") == 0);
    check("system", WEXITSTATUS(system("exit 3")) == 3);
    pid = fork();
    if (pid == 0) {
        sleep(30);
        _exit(0);
    }
    kill(pid, SIGTERM);
    check("wait_signaled", wait(&status) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    check("signal_raise", signal(SIGUSR1, on_signal) != SIG_ERR && raise(SIGUSR1) == 0 && got == SIGUSR1);
    check("ids", getpid() > 0 && getppid() >= 0 && getuid() == geteuid());
}

static void times(void) {
    struct timespec a, b, nap = {0, 20000000};
    check("time", time(NULL) > 1700000000);
    check("clock_gettime", clock_gettime(CLOCK_MONOTONIC, &a) == 0);
    check("nanosleep", nanosleep(&nap, NULL) == 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    check("slept", (b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec) >= 20000000L);
}

// The hardened allocator (ADR 0094), on Slate only (the host's is not
// ours): freeing a block twice, or a pointer into a block, stops the
// program with SIGABRT.
static void heap(void) {
    if (access("/proc/sys/slate", F_OK) != 0)
        return;
    for (int k = 0; k < 2; k++) {
        pid_t pid = fork();
        if (pid == 0) {
            char *volatile p = malloc(40);
            if (k == 0) {
                free(p);
                free(p);
            } else {
                char *volatile inside = p + 8;
                free(inside);
            }
            _exit(0);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        check(k == 0 ? "double_free_caught" : "bad_free_caught", WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT);
    }
}

int main(int argc, char **argv) {
    check("argv", argc >= 1 && strstr(argv[0], "native-libc") != NULL);
    check("environ", environ != NULL && getenv("PATH") != NULL);
    char dir[64];
    snprintf(dir, sizeof dir, "/tmp/nlibc-%d", getpid());
    strings();
    memory();
    heap();
    environment();
    files(dir);
    processes();
    times();
    check("atexit", atexit(at_exit_hook) == 0 && !exit_hook_ran);
    return failures;
}
