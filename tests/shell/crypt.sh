#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# slate-crypt (ADR 0039) on /dev/vde, an empty disk of its own: formatting,
# key slots, opening and closing after boot, the header's copy.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS crypt::$name"
    else
        echo "SLATE-TEST: FAIL crypt::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
D=/dev/vde
DATA="secret data on the encrypted disk"
dm_of() { sed -n 's|.* is open as /dev/\(dm-[0-9]*\)$|\1|p'; }

printf 'disk-pass1\ndisk-pass1\n' | slate-crypt format $D > /tmp/crypt.out 2>&1
check format "$(slate-crypt status $D | grep -c 'slot 0: password')" 1
check short_password "$(printf 'abc\nabc\n' | slate-crypt add-password $D 2>&1 | grep -c 'does not unlock')" 1

printf 'disk-pass1\n' | slate-crypt add-recovery-key $D > /tmp/rk.out 2>&1
rk=$(grep -o '[0-9A-Z]\{4\}\(-[0-9A-Z]\{4\}\)\{7\}' /tmp/rk.out)
check recovery_key_shown "$(echo "$rk" | wc -c | tr -d ' ')" 40
check recovery_slot "$(slate-crypt status $D | grep -c 'slot 1: recovery key')" 1

dm=$(printf 'disk-pass1\n' | slate-crypt open $D | dm_of)
check opened "$(echo $dm | grep -c '^dm-[0-9]')" 1
check slaves "$(ls /sys/block/$dm/slaves)" vde
check busy "$(printf 'disk-pass1\n' | slate-crypt open $D 2>&1 | grep -c 'open already')" 1
echo "$DATA" > /dev/$dm
check read_back "$(head -c 33 /dev/$dm)" "$DATA"
check ciphertext "$(head -c 1048609 $D | tail -c 33 | grep -c secret)" 0
# TRIM through the mapped device reaches the disk (QEMU unmaps it).
blkdiscard -o 0 -l 65536 /dev/$dm
check discard_passes_through "$(head -c 1048609 $D | tail -c 33 | tr -d '\000' | wc -c | tr -d ' ')" 0
echo "$DATA" > /dev/$dm
slate-crypt close $dm > /dev/null
check closed "$(ls /sys/block | grep -c "^$dm\$")" 0

# The recovery key, typed in lower case without dashes.
typed=$(echo "$rk" | tr -d '-' | tr 'A-Z' 'a-z')
dm=$(echo "$typed" | slate-crypt open $D | dm_of)
check recovery_opens "$(head -c 33 /dev/$dm)" "$DATA"
slate-crypt close $dm > /dev/null

printf 'disk-pass1\ndisk-pass2\ndisk-pass2\n' | slate-crypt change-password $D > /dev/null 2>&1
check old_password_fails "$(printf 'disk-pass1\n' | slate-crypt open $D 2>&1 | grep -c 'does not unlock')" 1
dm=$(printf 'disk-pass2\n' | slate-crypt open $D | dm_of)
check new_password_opens "$(head -c 33 /dev/$dm)" "$DATA"
slate-crypt close $dm > /dev/null

# The first copy of the header damaged: the copy opens it, repair rewrites.
printf 'X' > $D
check damaged "$(slate-crypt status $D | grep -c 'first copy is damaged')" 1
dm=$(printf 'disk-pass2\n' | slate-crypt open $D | dm_of)
check opens_from_copy "$(head -c 33 /dev/$dm)" "$DATA"
slate-crypt close $dm > /dev/null
slate-crypt repair $D > /dev/null
check repaired "$(slate-crypt status $D | grep -c 'both copies read')" 1

# Slots go, but never the last one, nor by its own key.
check own_slot "$(printf 'disk-pass2\n' | slate-crypt remove-slot $D 0 2>&1 | grep -c 'another slot')" 1
printf 'disk-pass2\n' | slate-crypt remove-slot $D 1 > /dev/null 2>&1
check removed "$(slate-crypt status $D | grep -c 'recovery key')" 0
check last_slot "$(slate-crypt remove-slot $D 0 2>&1 | grep -c 'last key slot')" 1
exit $fail
