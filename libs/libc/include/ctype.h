/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <ctype.h> (C11 7.4), the "C" locale only. */
#ifndef _CTYPE_H
#define _CTYPE_H
int isalnum(int c);
int isalpha(int c);
int isblank(int c);
int iscntrl(int c);
int isdigit(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);
int tolower(int c);
int toupper(int c);
#endif
