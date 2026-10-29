/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <stdlib.h> (C11 7.22, POSIX additions). No
   floating point yet (docs/GAPS.md). */
#ifndef _STDLIB_H
#define _STDLIB_H
#include <stddef.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 2147483647
void *malloc(size_t size);
void *calloc(size_t n, size_t size);
void *realloc(void *p, size_t size);
void free(void *p);
_Noreturn void exit(int status);
_Noreturn void _Exit(int status);
_Noreturn void abort(void);
int atexit(void (*fn)(void));
char *getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int system(const char *command);
int atoi(const char *s);
long atol(const char *s);
long long atoll(const char *s);
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
long long strtoll(const char *s, char **end, int base);
unsigned long long strtoull(const char *s, char **end, int base);
double strtod(const char *s, char **end);
float strtof(const char *s, char **end);
double atof(const char *s);
int abs(int x);
long labs(long x);
long long llabs(long long x);
int rand(void);
void srand(unsigned seed);
void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
#endif
