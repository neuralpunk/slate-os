#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Dynamically linked Alpine programs (musl's dynamic loader) in a chroot.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS alpine::$name"
    else
        echo "SLATE-TEST: FAIL alpine::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
A=/alpine
check dynamic_busybox "$(chroot $A /bin/busybox echo dyn-ok)" dyn-ok
check release "$(chroot $A cat /etc/alpine-release)" 3.22.6
check shell_pipeline "$(chroot $A /bin/sh -c 'echo a b c | wc -w')" 3
check chroot_root "$(chroot $A /bin/sh -c 'cd /..; pwd; ls / | grep -c alpine-release')" "/
0"
v=$(chroot $A apk --version)
case "$v" in apk-tools*) v=ok ;; esac
check apk_version "$v" ok
check apk_info "$(chroot $A apk info 2>/dev/null | grep -c '^musl$')" 1
check ldd "$(chroot $A /lib/ld-musl-x86_64.so.1 --list /bin/busybox 2>&1 | grep -c 'libc.musl-x86_64.so.1 =>')" 1
mkdir -p $A/proc && mount -t proc proc $A/proc
check proc_in_chroot "$(chroot $A cat /proc/self/comm)" cat
umount $A/proc
exit $fail
