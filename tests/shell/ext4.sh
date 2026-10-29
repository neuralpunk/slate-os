#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# ext4 on /dev/vdc (made by xtask with mkfs.ext4 -d): read what the host
# put there, then write; xtask runs e2fsck and debugfs on the image after
# the run to check what was written.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS ext4::$name"
    else
        echo "SLATE-TEST: FAIL ext4::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
M=/mnt/ext4
mkdir -p $M
# Online discard throughout: freed blocks are discarded once committed
# (the host's e2fsck and debugfs checks would see anything lost).
mount -t ext4 -o discard /dev/vdc $M
check mounted "$(grep -c " $M ext4" /proc/mounts)" 1
check read_small "$(cat $M/hello.txt)" "hello from the host"
# mount -o bind shows the same tree elsewhere.
mkdir -p /mnt/bind && mount -o bind $M /mnt/bind
check bind_mount "$(cat /mnt/bind/hello.txt)" "hello from the host"
umount /mnt/bind
check read_big "$(md5sum $M/big.bin | cut -d' ' -f1)" "$(cat $M/big.md5)"
check read_dir "$(ls $M/many | wc -l)" 500
check symlink "$(readlink $M/link)" "hello.txt"
check through_symlink "$(cat $M/link)" "hello from the host"
# O_DIRECT (ADR 0145): written through and dropped from the page
# cache, read back the same way; O_NOATIME for the owner.
check dd_direct "$(dd if=$M/big.bin of=$M/direct.bin bs=64k oflag=direct status=none && dd if=$M/direct.bin bs=64k iflag=direct,noatime status=none | md5sum | cut -d' ' -f1)" "$(cat $M/big.md5)"
check dd_direct_blocks "$(sync; stat -c %b $M/direct.bin)" "$(stat -c %b $M/big.bin)"
rm -f $M/direct.bin
# O_DIRECT's alignment (ADR 0162): a 1000-byte block is refused (EINVAL,
# as Linux's ext4 does); a short last block goes out without O_DIRECT, as
# GNU's dd does it.
check dd_direct_unaligned "$(dd if=/dev/zero of=$M/u.bin bs=1000 count=1 oflag=direct status=none 2>&1; echo $?)" "dd: error writing '$M/u.bin': Invalid argument
1"
head -c 5000 $M/big.bin > $M/five.bin
check dd_direct_short_last "$(dd if=$M/five.bin of=$M/u.bin bs=4096 oflag=direct status=none && cmp $M/five.bin $M/u.bin && echo same)" "same"
rm -f $M/u.bin $M/five.bin
# Access times (ADR 0162): relatime by default, so an old one is brought
# up to date by a read and a recent one is left; O_NOATIME leaves it;
# mounted noatime, nothing does.
check relatime_shown "$(grep " $M ext4" /proc/mounts | grep -c relatime)" 1
touch -a -d 2020-01-01 $M/hello.txt
cat $M/hello.txt >/dev/null
check atime_updated "$(test "$(stat -c %X $M/hello.txt)" -gt 1700000000 && echo yes)" yes
touch -a -d 2020-01-01 $M/hello.txt
dd if=$M/hello.txt iflag=noatime status=none >/dev/null
check atime_noatime_flag "$(stat -c %X $M/hello.txt)" 1577836800
mount -o remount,noatime $M
check noatime_shown "$(grep " $M ext4" /proc/mounts | grep -c 'rw,noatime')" 1
cat $M/hello.txt >/dev/null
check atime_noatime_mount "$(stat -c %X $M/hello.txt)" 1577836800
mount -o remount $M
ls $M/many >/dev/null
check stat_type "$(stat -c %F $M/dir)" "directory"
check statfs "$(stat -f -c %T $M)" "ext2/ext3"

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
# Writing.
echo "written by slate" > $M/new.txt
check write_small "$(cat $M/new.txt)" "written by slate"
dd if=/dev/urandom of=$M/rand bs=65536 count=40 2>/dev/null
md5sum $M/rand | cut -d' ' -f1 > $M/rand.md5
check write_big "$(stat -c %s $M/rand)" 2621440
mkdir -p $M/d1/d2/d3
echo deep > $M/d1/d2/d3/f
mv $M/d1/d2 $M/moved
check rename_dir "$(cat $M/moved/d3/f)" deep
check dotdot "$(cd $M/moved/d3/.. && pwd)" "$M/moved"
ln -s new.txt $M/newlink
ln $M/new.txt $M/hardlink
check hardlink "$(stat -c %h $M/new.txt)" 2
chmod 600 $M/new.txt
check chmod "$(stat -c %a $M/hardlink)" 600
for i in $(seq 1 300); do echo $i > $M/many/n$i; done
rm $M/many/f1*
check many "$(ls $M/many | wc -l)" "$((500 - 111 + 300))"
rm -r $M/dir
check rm_r "$(ls $M | grep -c '^dir$')" 0
cp /bin/busybox $M/busybox
check exec_from_ext4 "$($M/busybox echo ran-from-ext4)" ran-from-ext4
: > $M/truncated
echo 0123456789 > $M/truncated
truncate -s 4 $M/truncated 2>/dev/null || dd if=/dev/null of=$M/truncated bs=1 seek=4 2>/dev/null
check truncate "$(cat $M/truncated)" 0123
# The page cache: write-back of write(2) and of shared mappings (checked
# again below, after the unmount).
/test/pagecache write $M ext4 || fail=$((fail + 1))
# fstrim discards the free space; a tmpfs takes none.
check fstrim "$(fstrim -v $M | grep -c 'bytes) trimmed$')" 1
check fstrim_unsupported "$(fstrim /tmp 2>&1 | grep -c 'not supported')" 1
# The periodic trim (ADR 0122): due with no record of the last one, then
# not again until the period has passed.
rm -f /var/lib/slate/fstrim
check fstrim_periodic "$(fstrim --every 7 --once -v | grep -c "^$M: .*trimmed")" 1
check fstrim_recorded "$(test -s /var/lib/slate/fstrim && echo yes)" yes
check fstrim_not_due "$(fstrim --every 7 --once -v)" "fstrim: not due yet"
rm -f /var/lib/slate/fstrim
# Persisted across unmount and a read-only mount.
umount $M
check unmounted "$(grep -c " $M " /proc/mounts)" 0
mount -t ext4 -o ro /dev/vdc $M
check persisted "$(cat $M/new.txt)" "written by slate"
check persisted_big "$(md5sum $M/rand | cut -d' ' -f1)" "$(cat $M/rand.md5)"
/test/pagecache verify $M ext4 || fail=$((fail + 1))
echo x > $M/ro-write 2>/dev/null
check read_only "$?" 1
umount $M
# A file deleted while still open stays until its last user is gone; one
# still open at shutdown is freed when the file system closes (the host's
# e2fsck must find no orphan).
mount -t ext4 /dev/vdc $M
sleep 600 > $M/orphan &
# The background job creates the file; remove it only once it exists.
while [ ! -e $M/orphan ]; do :; done
rm $M/orphan
check orphan_unlinked "$(ls $M | grep -c orphan)" 0
exit $fail
