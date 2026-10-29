#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SlateFS through the system calls (ADR 0026), on /dev/vdd, a disk xtask
# makes with Slate's slatefs tool and checks with it afterwards.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS slatefs::$name"
    else
        echo "SLATE-TEST: FAIL slatefs::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
M=/mnt/sfs
mkdir -p $M $M-snap
mount -t slatefs -o discard /dev/vdd $M
check mounted "$(grep -c " $M slatefs" /proc/mounts)" 1
check read_host_file "$(cat $M/hello.txt)" "hello from the host"
echo "written by slate" > $M/new.txt
check write "$(cat $M/new.txt)" "written by slate"
head -c 2621440 /dev/urandom > $M/rand
md5sum $M/rand | cut -d' ' -f1 > $M/rand.md5
check big_file "$(md5sum $M/rand | cut -d' ' -f1)" "$(cat $M/rand.md5)"
mkdir -p $M/a/b/c && echo deep > $M/a/b/c/f && mv $M/a $M/moved
check rename_dir "$(cat $M/moved/b/c/f)" deep
ln $M/new.txt $M/hard && ln -s new.txt $M/soft
check links "$(stat -c %h $M/new.txt) $(cat $M/soft)" "2 written by slate"
for i in $(seq 1 300); do echo $i > $M/n$i; done
rm $M/n1*
check many "$(ls $M | grep -c '^n[0-9]')" 189
truncate -s 3 $M/new.txt
check truncate "$(cat $M/new.txt)" wri
# A read-only snapshot keeps the state it was taken in.
check snapshot "$(slatefs ctl $M snapshot snap ro)" 2
echo changed > $M/hello.txt
rm $M/rand
mount -t slatefs -o subvol=snap /dev/vdd $M-snap
check snapshot_kept "$(cat $M-snap/hello.txt) $(md5sum $M-snap/rand | cut -d' ' -f1)" "hello from the host $(cat $M/rand.md5)"
echo x > $M-snap/nope 2>/dev/null
check snapshot_read_only "$?" 1
check live_changed "$(cat $M/hello.txt)" changed
check list "$(slatefs ctl $M list | cut -d' ' -f2 | tr '\n' ,)" "root,snap,"
umount $M-snap
slatefs ctl $M delete snap
check deleted "$(slatefs ctl $M list | cut -d' ' -f2 | tr '\n' ,)" "root,"
/test/pagecache write $M slatefs || fail=$((fail + 1))
# The dentry cache (g022): misses are cached and forgotten when the name
# is made, by any call and through any mount; drop_caches drops the names
# nothing uses, which are found again.
for n in f d s h r; do test -e $M/dc-$n; done
echo x > $M/dc-f && mkdir $M/dc-d && ln -s dc-f $M/dc-s && ln $M/dc-f $M/dc-h
mv $M/dc-h $M/dc-r
check dcache_made "$(cat $M/dc-f $M/dc-s $M/dc-r; test -d $M/dc-d && echo d)" "x
x
x
d"
mkdir -p /mnt/dc-bind && mount -o bind $M /mnt/dc-bind
test -e /mnt/dc-bind/dc-b
echo b > $M/dc-b
check dcache_alias "$(cat /mnt/dc-bind/dc-b)" b
umount /mnt/dc-bind
dentries() { grep -o '[0-9]* dentries' /proc/slate_sched | cut -d' ' -f1; }
before=$(dentries)
echo 2 > /proc/sys/vm/drop_caches
check dcache_dropped "$(test "$(dentries)" -lt "$before" && echo fewer)" fewer
check dcache_found_again "$(cat $M/dc-r $M/dc-b)" "x
b"
rm -r $M/dc-f $M/dc-d $M/dc-s $M/dc-r $M/dc-b
check dcache_removed "$(ls $M | grep -c '^dc-')" 0
check fstrim "$(fstrim -v $M | grep -c 'bytes) trimmed$')" 1
# Commits write without the file system's lock: what changes while one
# is written goes into the next, intact.
( for i in $(seq 1 40); do sync; done ) &
syncer=$!
for i in $(seq 1 200); do echo "c$i" > $M/c$i; done
rm $M/c1*
wait $syncer
check during_commits "$(ls $M | grep -c '^c[0-9]') $(cat $M/c99)" "89 c99"
sync
umount $M
check unmounted "$(grep -c " $M " /proc/mounts)" 0
# What the page cache wrote back, read from a fresh mount.
mount -t slatefs /dev/vdd $M
/test/pagecache verify $M slatefs || fail=$((fail + 1))
check during_commits_kept "$(ls $M | grep -c '^c[0-9]') $(cat $M/c99) $(cat $M/c200)" "89 c99 c200"
umount $M
exit $fail
