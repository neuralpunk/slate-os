// SPDX-License-Identifier: MIT OR Apache-2.0
// rseq(2) (ADR 0115): registration and its errors, the CPU fields, and
// critical sections aborted by a signal and by preemption. The structures
// are the man page's (librseq's rseq.2); each expectation is what Linux
// was seen to do on the host.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("SLATE-TEST: %s user::rseq::%s\n", ok ? "PASS" : "FAIL", name);
    fflush(stdout);
    if (!ok) failures++;
}

struct rs { uint32_t cpu_id_start, cpu_id; uint64_t rseq_cs; uint32_t flags, node_id, mm_cid; char pad[92]; } __attribute__((aligned(32)));
struct cs { uint32_t version, flags; uint64_t start_ip, post_commit_offset, abort_ip; } __attribute__((aligned(32)));
#define SIG 0x53053053u
#define UNREGISTER 1

static __thread struct rs R;

/* A critical section that loops until it is aborted: it returns 1 from
   its abort handler (whose 4 bytes before hold the signature), 0 never.
   bad_loop's signature is wrong. */
extern char cs_start[], cs_end[], cs_abort[], bad_start[], bad_end[], bad_abort[];
long cs_loop(uint64_t *slot, struct cs *d);
long bad_loop(uint64_t *slot, struct cs *d);
__asm__(".text\n"
        ".globl cs_loop\ncs_loop:\n mov %rsi,(%rdi)\n"
        ".globl cs_start\ncs_start:\n jmp cs_start\n"
        ".globl cs_end\ncs_end:\n xor %eax,%eax\n ret\n"
        " .long 0x53053053\n"
        ".globl cs_abort\ncs_abort:\n mov $1,%eax\n ret\n"
        ".globl bad_loop\nbad_loop:\n mov %rsi,(%rdi)\n"
        ".globl bad_start\nbad_start:\n jmp bad_start\n"
        ".globl bad_end\nbad_end:\n xor %eax,%eax\n ret\n"
        " .long 0x12345678\n"
        ".globl bad_abort\nbad_abort:\n mov $1,%eax\n ret\n");

static long rseq(void *area, uint32_t len, int flags, uint32_t sig) { return syscall(SYS_rseq, area, len, flags, sig); }

static volatile int hits;
static void handler(int s) { (void)s; hits++; }

static void *thread_registers(void *x) {
    (void)x;
    R.cpu_id = -1;
    return (void *)(long)(rseq(&R, 32, 0, SIG) == 0);
}

static struct cs D;

int main(int argc, char **argv) {
    if (argc > 1) {
        /* After execve: nothing registered, so this registers. */
        R.cpu_id = -1;
        return rseq(&R, 32, 0, SIG) == 0 ? 0 : 1;
    }
    static struct rs other __attribute__((aligned(32)));
    R.cpu_id = -1;
    /* Registration's errors. */
    check("unregister_unregistered", rseq(&R, 32, UNREGISTER, SIG) == -1 && errno == EINVAL);
    check("len_31", rseq(&R, 31, 0, SIG) == -1 && errno == EINVAL);
    /* The features' size and alignment (librseq's rseq.2): an area may be
       larger than 32 bytes, aligned. The values are Slate's (features
       through mm_cid); Linux 7.2 says 33 and 64. */
    check("auxv_feature_size", getauxval(27) == 28 && getauxval(28) == 32);
    check("len_64", rseq(&other, 64, 0, SIG) == 0 && rseq(&other, 64, UNREGISTER, SIG) == 0);
    check("unaligned", rseq((char *)&other + 8, 32, 0, SIG) == -1 && errno == EINVAL);
    check("unknown_flags", rseq(&R, 32, 0x80, SIG) == -1 && errno == EINVAL);
    check("bad_address", rseq((void *)0x10000, 32, 0, SIG) == -1 && errno == EFAULT);
    /* Registered: the CPU fields say where the thread runs. */
    check("register", rseq(&R, 32, 0, SIG) == 0);
    check("cpu_fields", R.cpu_id == R.cpu_id_start && R.cpu_id < 1024 && R.rseq_cs == 0);
    check("node_and_cid", R.node_id == 0 && R.mm_cid < (uint32_t)sysconf(_SC_NPROCESSORS_CONF));
    check("same_again_busy", rseq(&R, 32, 0, SIG) == -1 && errno == EBUSY);
    check("other_sig", rseq(&R, 32, 0, SIG + 1) == -1 && errno == EPERM);
    check("other_len", rseq(&R, 64, 0, SIG) == -1 && errno == EINVAL);
    check("other_area", rseq(&other, 32, 0, SIG) == -1 && errno == EINVAL);
    check("unregister_wrong_sig", rseq(&R, 32, UNREGISTER, SIG + 1) == -1 && errno == EPERM);
    check("unregister_other_area", rseq(&other, 32, UNREGISTER, SIG) == -1 && errno == EINVAL);
    check("unregister_flags", rseq(&R, 32, 3, SIG) == -1 && errno == EINVAL);
    check("unregister", rseq(&R, 32, UNREGISTER, SIG) == 0 && R.cpu_id == (uint32_t)-1 && R.cpu_id_start == 0);
    check("register_again", rseq(&R, 32, 0, SIG) == 0);
    /* A signal in the section: it starts over at its abort handler, and
       rseq_cs is cleared. */
    signal(SIGALRM, handler);
    D.start_ip = (uint64_t)cs_start;
    D.post_commit_offset = (uint64_t)(cs_end - cs_start);
    D.abort_ip = (uint64_t)cs_abort;
    struct itimerval it = {{0, 0}, {0, 20000}};
    setitimer(ITIMER_REAL, &it, 0);
    check("signal_aborts", cs_loop(&R.rseq_cs, &D) == 1 && R.rseq_cs == 0);
    /* A signal outside the section clears rseq_cs too. */
    R.rseq_cs = (uint64_t)&D;
    hits = 0;
    setitimer(ITIMER_REAL, &it, 0);
    while (!hits) {
    }
    check("signal_outside_clears", R.rseq_cs == 0);
    /* The wrong signature before the abort handler: SIGSEGV. */
    pid_t c = fork();
    if (c == 0) {
        static struct cs b;
        b.start_ip = (uint64_t)bad_start;
        b.post_commit_offset = (uint64_t)(bad_end - bad_start);
        b.abort_ip = (uint64_t)bad_abort;
        setitimer(ITIMER_REAL, &it, 0);
        bad_loop(&R.rseq_cs, &b);
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    check("bad_signature_segv", WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    /* fork keeps the registration; a new thread and execve start without. */
    c = fork();
    if (c == 0) _exit(rseq(&R, 32, 0, SIG) == -1 && errno == EBUSY ? 0 : 1);
    waitpid(c, &st, 0);
    check("fork_inherits", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    pthread_t t;
    void *ok = 0;
    pthread_create(&t, 0, thread_registers, 0);
    pthread_join(t, &ok);
    check("thread_starts_without", ok != 0);
    c = fork();
    if (c == 0) {
        execl("/proc/self/exe", argv[0], "exec", (char *)0);
        _exit(9);
    }
    waitpid(c, &st, 0);
    check("exec_starts_without", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* Preemption: two sections looping on one CPU, no signals; each is
       switched away from and aborted. */
    signal(SIGALRM, SIG_DFL);
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    pid_t k[2];
    for (int i = 0; i < 2; i++) {
        k[i] = fork();
        if (k[i] == 0) {
            sched_setaffinity(0, sizeof one, &one);
            _exit(cs_loop(&R.rseq_cs, &D) == 1 && R.cpu_id == 0 ? 0 : 1);
        }
    }
    int aborted = 0;
    for (int i = 0; i < 2; i++) {
        int done = 0;
        for (int w = 0; w < 100 && !done; w++) {
            if (waitpid(k[i], &st, WNOHANG) == k[i]) {
                done = 1;
            } else {
                struct timespec ts = {0, 50000000};
                nanosleep(&ts, 0);
            }
        }
        if (!done) {
            kill(k[i], SIGKILL);
            waitpid(k[i], &st, 0);
        }
        aborted += done && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }
    check("preemption_aborts", aborted == 2);
    return failures != 0;
}
