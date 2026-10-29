#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Discards (TRIM, ADR 0039) through the drivers that take them: AHCI
# (/dev/sda) and NVMe (/dev/nvme0n1p1, through a partition). Bytes
# written, then discarded, read back as zeros (QEMU unmaps them in the raw
# images). crypt.sh does virtio-blk under a mapped device.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS discard::$name"
    else
        echo "SLATE-TEST: FAIL discard::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
trim() {
    head -c 65536 /dev/zero | tr '\000' 'A' > $1
    check ${2}_written "$(head -c 65536 $1 | tr -d 'A' | wc -c | tr -d ' ')" 0
    blkdiscard -l 64K $1
    check ${2}_discarded "$(head -c 65536 $1 | tr -d '\000' | wc -c | tr -d ' ')" 0
}
trim /dev/sda ahci
trim /dev/nvme0n1p1 nvme
check unaligned "$(blkdiscard -o 1 -l 512 /dev/sda 2>&1 | grep -c 'Invalid argument')" 1
check past_the_end "$(blkdiscard -o 64M -l 512 /dev/sda 2>&1 | grep -c 'Invalid argument')" 1
exit $fail
