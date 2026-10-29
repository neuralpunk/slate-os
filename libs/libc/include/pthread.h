/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031, ADR 0073): <pthread.h> (POSIX threads). The
 * object layouts are slate-libc's own; all-zero objects are the static
 * initialisers. Not provided: cancellation, pthread_kill/sigmask,
 * barriers, spin locks, scheduling, process-shared and robust mutexes. */
#ifndef _PTHREAD_H
#define _PTHREAD_H
#include <sys/types.h>
#include <time.h>

typedef unsigned long pthread_t;
typedef struct {
    unsigned long __stack;
    int __detached;
    int __reserved[13];
} pthread_attr_t;
typedef struct {
    unsigned int __lock;
    int __kind;
    unsigned int __owner;
    unsigned int __count;
    long __reserved[3];
} pthread_mutex_t;
typedef struct {
    int __kind;
} pthread_mutexattr_t;
typedef struct {
    unsigned int __seq;
    int __clock;
    long __reserved[5];
} pthread_cond_t;
typedef struct {
    int __clock;
} pthread_condattr_t;
typedef struct {
    unsigned int __lock;
    unsigned int __seq;
    unsigned int __readers;
    unsigned int __writer;
    long __reserved[4];
} pthread_rwlock_t;
typedef struct {
    int __reserved;
} pthread_rwlockattr_t;
typedef int pthread_once_t;
typedef unsigned int pthread_key_t;

#define PTHREAD_MUTEX_INITIALIZER {0}
#define PTHREAD_COND_INITIALIZER {0}
#define PTHREAD_RWLOCK_INITIALIZER {0}
#define PTHREAD_ONCE_INIT 0
#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1
#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT PTHREAD_MUTEX_NORMAL
#define PTHREAD_KEYS_MAX 128
#define PTHREAD_DESTRUCTOR_ITERATIONS 4

int pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*start)(void *), void *arg);
int pthread_join(pthread_t t, void **result);
int pthread_detach(pthread_t t);
pthread_t pthread_self(void);
int pthread_equal(pthread_t a, pthread_t b);
_Noreturn void pthread_exit(void *result);

int pthread_attr_init(pthread_attr_t *a);
int pthread_attr_destroy(pthread_attr_t *a);
int pthread_attr_setstacksize(pthread_attr_t *a, size_t size);
int pthread_attr_getstacksize(const pthread_attr_t *a, size_t *size);
int pthread_attr_setdetachstate(pthread_attr_t *a, int state);
int pthread_attr_getdetachstate(const pthread_attr_t *a, int *state);

int pthread_mutexattr_init(pthread_mutexattr_t *a);
int pthread_mutexattr_destroy(pthread_mutexattr_t *a);
int pthread_mutexattr_settype(pthread_mutexattr_t *a, int kind);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *a, int *kind);
int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a);
int pthread_mutex_destroy(pthread_mutex_t *m);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_trylock(pthread_mutex_t *m);
int pthread_mutex_timedlock(pthread_mutex_t *m, const struct timespec *at);
int pthread_mutex_unlock(pthread_mutex_t *m);

int pthread_condattr_init(pthread_condattr_t *a);
int pthread_condattr_destroy(pthread_condattr_t *a);
int pthread_condattr_setclock(pthread_condattr_t *a, clockid_t clock);
int pthread_condattr_getclock(const pthread_condattr_t *a, clockid_t *clock);
int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a);
int pthread_cond_destroy(pthread_cond_t *c);
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *at);
int pthread_cond_signal(pthread_cond_t *c);
int pthread_cond_broadcast(pthread_cond_t *c);

int pthread_rwlock_init(pthread_rwlock_t *l, const pthread_rwlockattr_t *a);
int pthread_rwlock_destroy(pthread_rwlock_t *l);
int pthread_rwlock_rdlock(pthread_rwlock_t *l);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *l);
int pthread_rwlock_wrlock(pthread_rwlock_t *l);
int pthread_rwlock_trywrlock(pthread_rwlock_t *l);
int pthread_rwlock_unlock(pthread_rwlock_t *l);

int pthread_once(pthread_once_t *once, void (*f)(void));
int pthread_key_create(pthread_key_t *key, void (*dtor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
#endif
