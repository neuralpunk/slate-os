#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# The shell (chalk) and Slate's tools on Slate.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS shell::$name"
    else
        echo "SLATE-TEST: FAIL shell::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}

check arithmetic "$((6 * 7))" 42
check pipeline "$(echo one two three | wc -w | tr -d ' ')" 3
check subshell "$(echo hi | tr a-z A-Z)" HI
check exit_status "$(false; echo $?)" 1
check and_or "$(true && echo yes || echo no)" yes
cd /tmp && echo data > f && check redirect "$(cat f)" data
echo more >> f && check append "$(wc -l < f | tr -d ' ')" 2
check here_doc "$(cat <<X
inline
X
)" inline
check glob "$(cd /etc && echo pass*)" passwd
check background "$( (sleep 0.1; echo bg) & wait )" bg
check loop "$(for i in 1 2 3; do printf $i; done)" 123
check function "$(f() { echo "arg=$1"; }; f x)" arg=x
check sed "$(echo hello | sed s/l/L/g)" heLLo
check dmesg "$(dmesg | grep -c "info  kernel: boot: ")" 1
check awk "$(echo 3 4 | awk '{print $1*$2}')" 12
check sort_uniq "$(printf 'b\na\nb\n' | sort | uniq | tr '\n' ,)" a,b,
check grep "$(grep -c root /etc/passwd)" 1
check ls_proc "$(ls /proc | grep -cx self)" 1
# Slate's own programs are told Slate; Linux programs, Linux (ADR 0153).
check uname "$(uname -s)" Slate
check uname_all "$(uname -a | grep -c Linux)" 0
check uname_os "$(uname -o)" SlateOS
check uname_linux "$(busybox uname -s)" Linux
check ostype "$(cat /proc/sys/kernel/ostype)-$(busybox cat /proc/sys/kernel/ostype)" Slate-Linux
check linux_release "$(cat /proc/sys/slate/linux_release)" 6.12.0-slate
# Slate's own programs use the native interface (ADR 0031); BusyBox, a
# Linux program, does not.
check native_shell "$(grep "^pid $$ " /proc/slate_sched | grep -c ' native')" 1
check native_coreutils "$(sh -c 'exec grep "^pid $$ " /proc/slate_sched' | grep -c ' native')" 1
check domain_shell "$(grep Domain /proc/$$/status | cut -f2)" slate
check domain_busybox "$(busybox sh -c 'grep Domain /proc/$$/status; true' | cut -f2)" linux
check compat_status "$(slate-compat status)" "Linux compatibility mode is on"
echo 0 > /proc/sys/slate/linux_compat
refused=$(/test/hello 2>&1)
echo 1 > /proc/sys/slate/linux_compat
# The Linux domain's boundary (ADR 0032): BusyBox, a Linux program, may
# not signal or see this (Slate) shell, nor write the system tree; what it
# starts stays in the Linux domain, even Slate's own tools.
check linux_no_signal "$(busybox sh -c "kill -0 $$ 2>/dev/null && echo yes || echo no")" no
check linux_no_inspect "$(busybox sh -c "test -e /proc/$$/status && echo yes || echo no")" no
check linux_ro_system "$(busybox touch /etc/linux-was-here 2>/dev/null && echo yes || echo no)" no
check linux_ro_system_slate_tool "$(busybox sh -c 'touch /etc/linux-was-here 2>/dev/null && echo yes || echo no')" no
# Descriptors the Slate domain keeps (ADR 0098): one written into the
# system tree does not reach a Linux program; one into /tmp does.
: > /etc/kept-back
: > /tmp/passed-on
(exec 3>>/etc/kept-back 4>>/tmp/passed-on; busybox sh -c 'echo x >&3; echo y >&4' 2>/dev/null)
check fd_kept_back "$(wc -c < /etc/kept-back | tr -d ' ')-$(cat /tmp/passed-on)" 0-y
rm -f /etc/kept-back /tmp/passed-on
check sock_kept_back "$(/test/signed/native-abi keptsock)" "conn-closed pair-open"
check linux_sticky "$(busybox sh -c 'grep Domain /proc/self/status' | cut -f2)" linux
check linux_own_child "$(busybox sh -c 'sleep 5 & kill $!; wait $!; echo $?')" 143
check linux_writes_tmp "$(busybox touch /tmp/linux-ok && echo yes; rm -f /tmp/linux-ok)" yes
# Strict W^X in the Slate domain: the same native program refuses an RWX
# mapping signed (ADR 0090: the Slate domain) and allows it unsigned.
check wx_slate "$(/test/signed/native-abi wx)" "wx refused"
check wx_linux "$(/test/native-abi wx)" "wx allowed"
# The rest of W^X (ADR 0093): in the Slate domain a written mapping never
# becomes executable, anonymous memory is never executable, and a dual
# mapping (writable here, executable there) needs the JIT permission.
check wxrules_slate "$(/test/signed/native-abi wxrules)" "flip-refused anonx-refused jit-refused"
check wxrules_jit "$(/test/signed/native-abi-jit wxrules)" "flip-refused anonx-refused jit-works"
check wxrules_linux "$(/test/native-abi wxrules)" "flip-allowed anonx-allowed jit-works"
# The system image (ADR 0090): read-only to root as well, /etc not; no
# developer mode in the test image, and no way to turn it on.
check image_ro_create "$(touch /usr/share/slate-was-here 2>/dev/null && echo yes || echo no)" no
check image_ro_mkdir "$(mkdir /usr/lib/slate-was-here 2>/dev/null && echo yes || echo no)" no
check image_ro_chmod "$(chmod 755 /bin/etch 2>/dev/null && echo yes || echo no)" no
check image_ro_init "$(mv /init /init.moved 2>/dev/null && { mv /init.moved /init; echo yes; } || echo no)" no
check image_etc_rw "$(touch /etc/slate-rw && rm /etc/slate-rw && echo yes)" yes
check devmode_off "$(cat /proc/sys/slate/devmode)" 0
check devmode_stays_off "$(sh -c 'echo 1 > /proc/sys/slate/devmode' 2>/dev/null && echo yes || echo no)" no
# Signed programs (ADR 0090): Slate's own tools in the Slate domain from
# anywhere, an altered copy in the Linux domain.
cp /test/signed/native-abi /tmp/altered && printf x >> /tmp/altered
check altered_domain "$(/tmp/altered wx)" "wx allowed"
cp /bin/coreutils /tmp/cat
check copied_tool "$(/tmp/cat /proc/self/status | grep Domain | cut -f2)" slate
rm -f /tmp/altered /tmp/cat
# DRM (ADR 0033): the card's node and the sysfs entries libdrm reads.
check drm_node "$(ls /dev/dri)" card0
check drm_sysfs "$(cat /sys/class/drm/card0/dev)" 226:0
check drm_dev_char "$(grep -c DEVNAME=dri/card0 /sys/dev/char/226:0/uevent)" 1
# PCI in sysfs (M23 phase 7): q35's host bridge (Intel 82G33 MCH,
# 8086:29c0), the bus's links, a bound driver, and lspci over them.
pci=/sys/bus/pci/devices/0000:00:00.0
check pci_sysfs "$(cat $pci/vendor $pci/device $pci/class)" "0x8086
0x29c0
0x060000"
check pci_uevent "$(grep -c PCI_SLOT_NAME=0000:00:00.0 $pci/uevent)" 1
check pci_subsystem "$(ls $pci/subsystem/devices | grep -c 0000:00:00.0)" 1
check pci_config "$(head -c 4 $pci/config | od -An -tx1 | tr -d ' ')" 8680c029
check lspci "$(lspci -n -s 00:00.0 | cut -d' ' -f2-3)" "0600: 8086:29c0"
check lspci_all "$(lspci | wc -l | tr -d ' ')" "$(ls /sys/bus/pci/devices | wc -l | tr -d ' ')"
check lspci_driver "$(lspci -k | grep -c 'Kernel driver in use: virtio-blk')" \
    "$(for d in /sys/bus/pci/devices/*; do [ -d $d/driver ] && readlink $d/driver; done | grep -c /virtio-blk$)"
# UEFI variables through efivarfs (ADR 0088): BootOrder is there, and a
# variable of Slate's own is written, read back and deleted. BIOS boots
# have none.
if [ -d /sys/firmware/efi ]; then
    ev=/sys/firmware/efi/efivars
    # Mounted by rc.sysinit; these checks may run before it.
    grep -q " $ev efivarfs " /proc/mounts || mount -t efivarfs efivarfs $ev
    check efivars_mounted "$(grep -c " $ev efivarfs " /proc/mounts)" 1
    check efivars_bootorder "$(ls $ev | grep -c '^BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c$')" 1
    check efivars_attrs "$(od -An -tx1 -N4 $ev/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d ' ')" 07000000
    t=$ev/SlateTest-5a4d1c2e-8f3b-4c1a-9e7d-3b2a1c0d9e8f
    printf '\007\000\000\000hello' > $t
    check efivars_write "$(tail -c 5 $t)" hello
    rm $t
    check efivars_delete "$(ls $ev | grep -c '^SlateTest-')" 0
    # Vendor variables are immutable, appends append (tests/user/efivars.c).
    /test/efivars $ev
    check slate_boot_list "$(slate-boot list | grep -c '^BootOrder ')" 1
else
    check efivars_bios "$(ls /sys/firmware 2>/dev/null | grep -c efi)" 0
fi
check slate_mode_refuses "$(echo "$refused" | grep -c 'Linux compatibility mode is off')" 1
check linux_busybox "$(busybox sh -c 'grep "^pid $$ " /proc/slate_sched; true' | grep -c ' native')" 0
check mkdir_rm "$(mkdir -p /tmp/a/b/c && ls -d /tmp/a/b/c && rm -r /tmp/a && echo gone)" "/tmp/a/b/c
gone"
check trap "$(sh -c 'trap "echo caught" USR1; kill -USR1 $$; echo after')" "caught
after"
check kill_child "$(sh -c 'sleep 5 & kill $!; wait $!; echo $?')" 143
check proc_meminfo "$(grep -c MemTotal /proc/meminfo)" 1
# A read of /dev/zero or /dev/urandom fills the buffer (random(4): up to
# 32 MiB), not only the kernel's 64 KiB copy buffer.
check dev_zero_fill "$(dd if=/dev/zero bs=1M count=4 2>/dev/null | wc -c | tr -d ' ')" 4194304
check dev_urandom_fill "$(dd if=/dev/urandom bs=1M count=4 2>/dev/null | wc -c | tr -d ' ')" 4194304
check var_tmp "$(ls -ld /var/tmp | cut -c1-10)" drwxrwxrwt
# tmpfs(5)'s size and file limits are enforced: 8 KiB holds two pages.
mkdir -p /tmp/small && mount -t tmpfs -o size=8k,nr_inodes=3 tmpfs /tmp/small
check tmpfs_size "$(dd if=/dev/zero of=/tmp/small/f bs=4k count=4 2>/dev/null; wc -c < /tmp/small/f | tr -d ' ')" 8192
check tmpfs_inodes "$(touch /tmp/small/g; touch /tmp/small/h 2>/dev/null || echo full)" full
check tmpfs_bad_size "$(mount -t tmpfs -o size=lots tmpfs /tmp/small 2>/dev/null || echo refused)" refused
umount /tmp/small && rmdir /tmp/small
check dev_zero "$(head -c 4 /dev/zero | wc -c | tr -d ' ')" 4
# /proc/PID/io (proc(5)): cat, having read 10000 bytes, says so.
head -c 10000 /dev/zero > /tmp/z
check proc_io "$(cat /tmp/z /proc/self/io | tr -d '\000' | awk '/^rchar/ { r = ($2 >= 10000) } /^syscr/ { c = ($2 >= 1) } END { print r c }')" 11
rm -f /tmp/z
# /proc/PID/statm's shared, text and data pages and /proc/PID/wchan (ADR
# 0163): the shell has code, data and shared pages; a sleeping process
# names the call it sleeps in; top's memory fields read them.
set -- $(cat /proc/$$/statm)
check statm_parts "$(test "$3" -gt 0 && test "$4" -gt 0 && test "$6" -gt 0 && echo yes)" yes
busybox sleep 5 & sp=$!
sleep 1
check wchan_sleeping "$(case $(cat /proc/$sp/wchan) in *nanosleep) echo sleeps;; *) cat /proc/$sp/wchan;; esac)" sleeps
check wchan_running "$(cat /proc/self/wchan)" 0
mkdir -p /tmp/tc/slate && echo fields=PID,SHR,CODE,DATA,SWAP,WCHAN,COMMAND > /tmp/tc/slate/toprc
check top_memory "$(XDG_CONFIG_HOME=/tmp/tc top -b -n 1 -p $sp | awk '/^ *PID/ { getline; print ($3 > 0 && $4 > 0 && $5 == 0 && $6 ~ /nanosleep/) }')" 1
rm -r /tmp/tc
kill $sp
# awk -i inplace with no inplace.awk installed: Slate's own (ADR 0165).
printf 'one\ntwo\n' > /tmp/ip.txt
check awk_inplace "$(awk -i inplace -v INPLACE_SUFFIX=.orig '{ print toupper($0) }' /tmp/ip.txt; cat /tmp/ip.txt /tmp/ip.txt.orig | tr '\n' ,)" "ONE,TWO,one,two,"
rm -f /tmp/ip.txt /tmp/ip.txt.orig
check less_as_cat "$(printf 'a\nb\n' | less | wc -l | tr -d ' ')" 2
check chroot "$(cd /tmp && /bin/coreutils chroot / /bin/sh -c pwd)" /
check chroot_status "$(/bin/coreutils chroot /nonexistent true 2>/dev/null; echo $?) $(/bin/coreutils chroot / /nonexistent 2>/dev/null; echo $?)" "125 127"
# date -s and POSIX's date MMDDhhmm[[CC]YY][.ss] set the clock (put back after).
saved=$(date +%s)
check date_set "$(date -u -s '2030-01-02 03:04:05' +%F)" 2030-01-02
check date_set_kept "$(date -u +%Y)" 2030
check date_posix "$(date -u 010203042031.05 +%F)" 2031-01-02
check date_bad "$(date -s 'not a date' 2>&1 | grep -c 'invalid date')" 1
date -s "@$((saved + 2))" > /dev/null
check date_restored "$(( $(date +%s) - saved < 30 ))" 1
# Zones keep their history (ADR 0141): Britain kept summer time all year
# in 1970, Moscow's offset moved in 2011 and 2014.
check tz_history "$(TZ=Europe/London date -d @0 +'%H %Z')" "01 BST"
check tz_moscow "$(TZ=Europe/Moscow date -d @1350000000 +%z) $(TZ=Europe/Moscow date -d @1420000000 +%z)" "+0400 +0300"
check tz_back "$(TZ=Europe/Paris date -d '1990-07-01 12:00' +%s)" 646826400
check tz_in_string "$(date -d 'TZ="Europe/London" 1970-01-01 01:00' +%s)" 0
# dd's statistics on SIGUSR1 (ADR 0145), then the copy goes on.
rm -f /tmp/dd.err
(sleep 1; echo more) | dd of=/dev/null 2>/tmp/dd.err &
sleep 0.4
kill -USR1 $!
wait
check dd_usr1 "$(grep -c 'records in' /tmp/dd.err)" 2
check dd_noatime_owner "$(echo hi > /tmp/dd.na && dd if=/tmp/dd.na iflag=noatime status=none)" hi
# tput's own descriptions where there is no terminfo database (ADR
# 0144): clear with E3 unless -x, sgr, an unknown capability.
check tput_clear "$(tput -T xterm-256color clear | od -An -c | tr -s ' ')" " 033 [ H 033 [ 2 J 033 [ 3 J"
check tput_clear_x "$(tput -x -T xterm-256color clear | od -An -c | tr -s ' ')" " 033 [ H 033 [ 2 J"
check tput_sgr "$(tput -T xterm-256color sgr 0 1 0 0 0 1 0 0 0 | od -An -c | tr -s ' ')" " 033 [ 0 ; 1 ; 4 m 033 ( B"
check tput_unknown "$(tput -T linux nosuchcap 2>/dev/null; echo $?)" 4
exit $fail
