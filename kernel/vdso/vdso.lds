/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Symbol versions for the vDSO: the names and the LINUX_2.6 version are
   what C libraries look up (observed in musl's vdso lookup). */
LINUX_2.6 {
    global:
        __vdso_clock_gettime;
        __vdso_gettimeofday;
        __vdso_time;
        __vdso_getcpu;
        clock_gettime;
        gettimeofday;
        time;
        getcpu;
    local: *;
};
