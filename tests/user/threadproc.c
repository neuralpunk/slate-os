// SPDX-License-Identifier: MIT OR Apache-2.0
// A thread's own files in /proc/PID/task/TID (proc(5)): its ID, the name
// it gave itself, its status; and ps -L listing it, ps -H drawing the
// tree. Runs on the host too.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::threadproc::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

static long worker_tid;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t named = PTHREAD_COND_INITIALIZER, done = PTHREAD_COND_INITIALIZER;
static int ready, finish;

static void *worker(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "worker", 0, 0, 0);
    pthread_mutex_lock(&lock);
    worker_tid = syscall(SYS_gettid);
    ready = 1;
    pthread_cond_signal(&named);
    while (!finish) pthread_cond_wait(&done, &lock);
    pthread_mutex_unlock(&lock);
    return 0;
}

static int read_file(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, n - 1, f);
    buf[got] = 0;
    fclose(f);
    return (int)got;
}

/// The output of `cmd`, with at most `n` bytes.
static void run(const char *cmd, char *buf, size_t n) {
    FILE *p = popen(cmd, "r");
    size_t got = p ? fread(buf, 1, n - 1, p) : 0;
    buf[got] = 0;
    if (p) pclose(p);
}

int main(void) {
    prctl(PR_SET_NAME, "threadproc", 0, 0, 0);
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_mutex_lock(&lock);
    while (!ready) pthread_cond_wait(&named, &lock);
    pthread_mutex_unlock(&lock);

    char path[128], buf[4096], want[128];
    snprintf(path, sizeof path, "/proc/%d/task/%ld/comm", getpid(), worker_tid);
    check("thread_comm", read_file(path, buf, sizeof buf) > 0 && strcmp(buf, "worker\n") == 0);
    snprintf(path, sizeof path, "/proc/%d/task/%ld/stat", getpid(), worker_tid);
    snprintf(want, sizeof want, "%ld (worker) ", worker_tid);
    check("thread_stat", read_file(path, buf, sizeof buf) > 0 && strncmp(buf, want, strlen(want)) == 0);
    snprintf(path, sizeof path, "/proc/%d/task/%ld/status", getpid(), worker_tid);
    snprintf(want, sizeof want, "\nPid:\t%ld\n", worker_tid);
    check("thread_status", read_file(path, buf, sizeof buf) > 0 && strstr(buf, "Name:\tworker\n") && strstr(buf, want));
    snprintf(path, sizeof path, "/proc/%d/comm", getpid());
    check("process_comm", read_file(path, buf, sizeof buf) > 0 && strcmp(buf, "threadproc\n") == 0);
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", getpid(), getpid());
    check("main_thread_comm", read_file(path, buf, sizeof buf) > 0 && strcmp(buf, "threadproc\n") == 0);

    // ps -L lists both threads with their IDs and names.
    char cmd[128];
    snprintf(cmd, sizeof cmd, "ps -L -o lwp,comm -p %d", getpid());
    run(cmd, buf, sizeof buf);
    snprintf(want, sizeof want, "%ld worker", worker_tid);
    check("ps_threads", strstr(buf, want) && strstr(buf, "threadproc") && strstr(buf, "LWP"));
    // ps -H: a child indented under this process.
    int to_child[2];
    pipe(to_child);
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "tpchild", 0, 0, 0);
        char c;
        close(to_child[1]);
        read(to_child[0], &c, 1);
        _exit(0);
    }
    close(to_child[0]);
    usleep(100000);
    snprintf(cmd, sizeof cmd, "ps -H -o pid,comm -p %d,%d", getpid(), child);
    run(cmd, buf, sizeof buf);
    char *me = strstr(buf, " threadproc\n"), *kid = strstr(buf, "   tpchild\n");
    check("ps_tree", me && kid && me < kid);
    close(to_child[1]);
    waitpid(child, 0, 0);

    pthread_mutex_lock(&lock);
    finish = 1;
    pthread_cond_signal(&done);
    pthread_mutex_unlock(&lock);
    pthread_join(t, 0);
    return failures != 0;
}
