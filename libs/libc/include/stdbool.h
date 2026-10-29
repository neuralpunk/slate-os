/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-libc (ADR 0031): <stdbool.h> (C11 7.18). */
#ifndef _STDBOOL_H
#define _STDBOOL_H
#ifndef __cplusplus
#define bool _Bool
#define true 1
#define false 0
#endif
#define __bool_true_false_are_defined 1
#endif
