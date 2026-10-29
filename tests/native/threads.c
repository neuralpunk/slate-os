// SPDX-License-Identifier: MIT OR Apache-2.0
//
// slate-libc's threads (ADR 0073), checked from C: built by tools/slate-cc,
// run on Slate (native calls) and on the Linux host (cargo xtask check).
// Prints one line per check and exits with the number of failures.

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("native-threads: %s %s\n", ok ? "ok" : "FAIL", name);
    if (!ok)
        failures++;
}

// --- a shared counter under a mutex ---

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long counter;

static void *add(void *arg) {
    long n = (long)arg;
    for (long i = 0; i < n; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void *)(n * 2);
}

// --- thread-locals and errno ---

static __thread int mine = 5;
static __thread char big[3000];

static void *locals(void *arg) {
    int ok = mine == 5 && big[0] == 0 && big[2999] == 0;
    mine = (int)(long)arg;
    memset(big, 'x', sizeof big);
    // errno is per thread: this failure must not show in the main thread.
    errno = 0;
    ok = ok && close(-1) == -1 && errno == EBADF;
    sched_yield();
    ok = ok && mine == (int)(long)arg && big[1500] == 'x';
    return (void *)(long)ok;
}

// --- pthread_exit ---

static void *leaves(void *arg) {
    (void)arg;
    pthread_exit((void *)42);
}

// --- a condition variable: a one-slot queue ---

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcond = PTHREAD_COND_INITIALIZER;
static int slot, full, sum;

static void *consumer(void *arg) {
    (void)arg;
    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&qlock);
        while (!full)
            pthread_cond_wait(&qcond, &qlock);
        sum += slot;
        full = 0;
        pthread_cond_broadcast(&qcond);
        pthread_mutex_unlock(&qlock);
    }
    return NULL;
}

// --- once, keys ---

static pthread_once_t once = PTHREAD_ONCE_INIT;
static int once_runs;
static void init_once(void) { once_runs++; }

static pthread_key_t key;
static int destroyed;
static void destroy(void *v) {
    pthread_mutex_lock(&lock);
    destroyed += (int)(long)v;
    pthread_mutex_unlock(&lock);
}

static void *uses_key(void *arg) {
    pthread_once(&once, init_once);
    pthread_setspecific(key, arg);
    return pthread_getspecific(key);
}

// --- detached ---

static pthread_mutex_t dlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dcond = PTHREAD_COND_INITIALIZER;
static int detached_done;

static void *detached(void *arg) {
    (void)arg;
    pthread_mutex_lock(&dlock);
    detached_done = 1;
    pthread_cond_signal(&dcond);
    pthread_mutex_unlock(&dlock);
    return NULL;
}

static void *noop(void *arg) { return arg; }

// --- read-write lock ---

static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;

static void *try_write(void *arg) {
    (void)arg;
    return (void *)(long)pthread_rwlock_trywrlock(&rw);
}

int main(void) {
    pthread_t t[8];
    void *r;

    // Eight threads, 20000 increments each.
    int ok = 1;
    for (int i = 0; i < 8; i++)
        ok = ok && pthread_create(&t[i], NULL, add, (void *)20000L) == 0;
    long results = 0;
    for (int i = 0; i < 8; i++) {
        ok = ok && pthread_join(t[i], &r) == 0;
        results += (long)r;
    }
    check("mutex_counter", ok && counter == 160000 && results == 8 * 40000);

    // Thread-locals start from the program's image in each thread.
    mine = 9;
    big[0] = 'm';
    errno = ENOENT;
    ok = 1;
    for (int i = 0; i < 4; i++)
        ok = ok && pthread_create(&t[i], NULL, locals, (void *)(long)(100 + i)) == 0;
    for (int i = 0; i < 4; i++) {
        ok = ok && pthread_join(t[i], &r) == 0 && r == (void *)1;
    }
    check("thread_locals", ok && mine == 9 && big[0] == 'm' && big[1] == 0);
    check("errno_per_thread", errno == ENOENT);

    check("pthread_exit", pthread_create(&t[0], NULL, leaves, NULL) == 0 && pthread_join(t[0], &r) == 0 &&
                              r == (void *)42);
    check("self_equal", pthread_equal(pthread_self(), pthread_self()) && !pthread_equal(pthread_self(), t[0] + 1));
    check("join_self", pthread_join(pthread_self(), NULL) == EDEADLK);

    // Producer here, consumer there.
    ok = pthread_create(&t[0], NULL, consumer, NULL) == 0;
    for (int i = 1; i <= 100; i++) {
        pthread_mutex_lock(&qlock);
        while (full)
            pthread_cond_wait(&qcond, &qlock);
        slot = i;
        full = 1;
        pthread_cond_broadcast(&qcond);
        pthread_mutex_unlock(&qlock);
    }
    ok = ok && pthread_join(t[0], NULL) == 0;
    check("condvar_queue", ok && sum == 5050);

    // A deadline in the past times out at once; one 50 ms ahead after it.
    struct timespec now, at;
    clock_gettime(CLOCK_REALTIME, &now);
    pthread_mutex_lock(&qlock);
    int e1 = pthread_cond_timedwait(&qcond, &qlock, &now);
    at = now;
    at.tv_nsec += 50000000;
    if (at.tv_nsec >= 1000000000) {
        at.tv_sec++;
        at.tv_nsec -= 1000000000;
    }
    int e2 = pthread_cond_timedwait(&qcond, &qlock, &at);
    struct timespec after;
    clock_gettime(CLOCK_REALTIME, &after);
    pthread_mutex_unlock(&qlock);
    long waited = (after.tv_sec - now.tv_sec) * 1000 + (after.tv_nsec - now.tv_nsec) / 1000000;
    check("cond_timedwait", e1 == ETIMEDOUT && e2 == ETIMEDOUT && waited >= 45);

    // Once runs once; each thread's key value meets the destructor.
    ok = pthread_key_create(&key, destroy) == 0;
    for (int i = 0; i < 4; i++)
        ok = ok && pthread_create(&t[i], NULL, uses_key, (void *)(long)(i + 1)) == 0;
    for (int i = 0; i < 4; i++)
        ok = ok && pthread_join(t[i], &r) == 0 && r == (void *)(long)(i + 1);
    check("once", once_runs == 1);
    check("key_destructors", ok && destroyed == 1 + 2 + 3 + 4);

    // Recursive and error-checking mutexes.
    pthread_mutexattr_t ma;
    pthread_mutex_t rm;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&rm, &ma);
    ok = pthread_mutex_lock(&rm) == 0 && pthread_mutex_lock(&rm) == 0 && pthread_mutex_unlock(&rm) == 0 &&
         pthread_mutex_unlock(&rm) == 0 && pthread_mutex_unlock(&rm) == EPERM;
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&rm, &ma);
    ok = ok && pthread_mutex_lock(&rm) == 0 && pthread_mutex_lock(&rm) == EDEADLK && pthread_mutex_trylock(&rm) == EDEADLK &&
         pthread_mutex_unlock(&rm) == 0;
    check("mutex_kinds", ok);

    // A reader keeps a writer out.
    ok = pthread_rwlock_rdlock(&rw) == 0 && pthread_rwlock_rdlock(&rw) == 0;
    ok = ok && pthread_create(&t[0], NULL, try_write, NULL) == 0 && pthread_join(t[0], &r) == 0 && r == (void *)EBUSY;
    ok = ok && pthread_rwlock_unlock(&rw) == 0 && pthread_rwlock_unlock(&rw) == 0;
    ok = ok && pthread_create(&t[0], NULL, try_write, NULL) == 0 && pthread_join(t[0], &r) == 0 && r == (void *)0;
    check("rwlock", ok);

    // A detached thread, with a small stack.
    pthread_attr_t a;
    size_t size = 0;
    pthread_attr_init(&a);
    ok = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED) == 0 && pthread_attr_setstacksize(&a, 65536) == 0 &&
         pthread_attr_getstacksize(&a, &size) == 0 && size == 65536;
    ok = ok && pthread_create(&t[0], &a, detached, NULL) == 0;
    pthread_mutex_lock(&dlock);
    while (!detached_done)
        pthread_cond_wait(&dcond, &dlock);
    pthread_mutex_unlock(&dlock);
    check("detached", ok && detached_done);

    // Many threads one after another: their memory comes back.
    ok = 1;
    for (int i = 0; i < 300 && ok; i++)
        ok = pthread_create(&t[0], NULL, noop, (void *)(long)i) == 0 && pthread_join(t[0], &r) == 0 &&
             r == (void *)(long)i;
    for (int i = 0; i < 50 && ok; i++)
        ok = pthread_create(&t[0], &a, noop, NULL) == 0;
    check("many_threads", ok);

    printf("native-threads: %d failures\n", failures);
    return failures;
}
