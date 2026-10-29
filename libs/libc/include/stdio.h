/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <stdio.h> (C11 7.21). printf and scanf have the
   floating-point conversions (ADR 0074), but no long double (%Lf). */
#ifndef _STDIO_H
#define _STDIO_H
#include <stdarg.h>
#include <stddef.h>
typedef struct __slate_file FILE;
typedef long off_t;
extern FILE *const stdin;
extern FILE *const stdout;
extern FILE *const stderr;
#define EOF (-1)
#define BUFSIZ 4096
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
FILE *fopen(const char *path, const char *mode);
FILE *fdopen(int fd, const char *mode);
int fclose(FILE *f);
int fflush(FILE *f);
size_t fread(void *buf, size_t size, size_t n, FILE *f);
size_t fwrite(const void *buf, size_t size, size_t n, FILE *f);
int fgetc(FILE *f);
int getc(FILE *f);
int getchar(void);
int ungetc(int c, FILE *f);
char *fgets(char *s, int n, FILE *f);
int fputc(int c, FILE *f);
int putc(int c, FILE *f);
int putchar(int c);
int fputs(const char *s, FILE *f);
int puts(const char *s);
int fseek(FILE *f, long offset, int whence);
long ftell(FILE *f);
void rewind(FILE *f);
int feof(FILE *f);
int ferror(FILE *f);
void clearerr(FILE *f);
int fileno(FILE *f);
void perror(const char *s);
int remove(const char *path);
int rename(const char *from, const char *to);
int printf(const char *fmt, ...);
int fprintf(FILE *f, const char *fmt, ...);
int dprintf(int fd, const char *fmt, ...);
int sprintf(char *s, const char *fmt, ...);
int snprintf(char *s, size_t n, const char *fmt, ...);
int vprintf(const char *fmt, va_list ap);
int vfprintf(FILE *f, const char *fmt, va_list ap);
int vdprintf(int fd, const char *fmt, va_list ap);
int vsprintf(char *s, const char *fmt, va_list ap);
int vsnprintf(char *s, size_t n, const char *fmt, va_list ap);
int scanf(const char *fmt, ...);
int fscanf(FILE *f, const char *fmt, ...);
int sscanf(const char *s, const char *fmt, ...);
int vscanf(const char *fmt, va_list ap);
int vfscanf(FILE *f, const char *fmt, va_list ap);
int vsscanf(const char *s, const char *fmt, va_list ap);
#endif
