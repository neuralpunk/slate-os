#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# The Linux runtime's door (M31 phase 1): slate-linux runs a program of a
# runtime (the Alpine test load) in namespaces of its own, and entering
# takes little time: the median of five entries within its budget.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS linuxrt::$name"
    else
        echo "SLATE-TEST: FAIL linuxrt::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
# Entering the runtime (µs), budget from M31's measurements.
BUDGET_US=20000
export HOME=/root
check runs "$(slate-linux run --root /alpine /bin/cat /etc/alpine-release)" 3.22.6
# Its own /tmp, not the system's.
touch /tmp/linuxrt-mark
check own_tmp "$(slate-linux run --root /alpine /bin/sh -c 'ls /tmp | grep -c linuxrt-mark')" 0
rm -f /tmp/linuxrt-mark
times=""
for i in 1 2 3 4 5; do
    t=$(SLATE_LINUX_TIMING=1 slate-linux run --root /alpine /bin/true 2>&1 | sed -n 's/.*runtime entered \([0-9]*\) us.*/\1/p')
    times="$times $t"
done
median=$(for t in $times; do echo $t; done | sort -n | sed -n 3p)
echo "linuxrt: entering the runtime: $times us (median $median)"
ok=no
[ -n "$median" ] && [ "$median" -le $BUDGET_US ] && ok=yes
check entry_budget "$ok" yes
exit $fail
