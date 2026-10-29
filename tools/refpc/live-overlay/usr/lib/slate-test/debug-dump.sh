#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# The boot state dump of development live media (ADR 0076): on a machine
# worked remotely without a keyboard, a boot that cannot be reached over
# the network still explains itself. Every 10 s for two minutes it writes
# the kernel log, the network's and devices' state to the disk holding the
# live medium (the FAT volume labelled SLATE-LIVE at sector 2048), 320 MiB
# in, past the image. Then it restarts the machine, which comes back up in
# whatever the firmware boots by default, unless /run/debug-stay exists
# (touch it after logging in over SSH). Read it there with:
#   dd if=DISK bs=1M skip=320 count=16 | tr -d '\000' | sed -n '/DUMP-BEGIN/,/DUMP-END/p'
offset_mb=320

medium() {
    for d in /dev/nvme*n1 /dev/sd?; do
        [ -b "$d" ] || continue
        if dd if="$d" bs=512 skip=2048 count=1 2>/dev/null | strings | grep -q 'SLATE-LIVE'; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

dump() {
    {
        echo "SLATE-DEBUG-DUMP-BEGIN round $1, $(date)"
        uname -a
        cat /proc/cmdline
        echo "== ip"
        ip addr
        ip route
        echo "== netd"
        cat /run/netd/status
        tail -n 60 /var/log/services/netd.log
        echo "== /proc/net/dev"
        cat /proc/net/dev
        echo "== /proc/interrupts"
        cat /proc/interrupts
        echo "== /proc/meminfo"
        head -n 8 /proc/meminfo
        echo "== /var/log/messages"
        tail -n 100 /var/log/messages
        echo "== dmesg"
        dmesg
        echo "SLATE-DEBUG-DUMP-END"
    } > /run/debug-dump.txt 2>&1
    dd if=/run/debug-dump.txt of="$disk" bs=1M seek=$offset_mb conv=fsync 2>/dev/null
}

sleep 15
disk=$(medium) || disk=
round=0
while [ $round -lt 12 ]; do
    round=$((round + 1))
    [ -n "$disk" ] && dump $round
    sleep 10
done
[ -e /run/debug-stay ] || reboot
while :; do
    sleep 3600
done
