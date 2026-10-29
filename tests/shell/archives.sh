#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# The compressors and tar on Slate (ADR 0140): each codec's round trip,
# tar through every codec, sparse files, appending, deleting and
# stripping components, on Slate's kernel and its filesystems.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS archives::$name"
    else
        echo "SLATE-TEST: FAIL archives::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
d=$(mktemp -d /tmp/archives.XXXXXX) || exit 1
cd "$d" || exit 1
seq 1 20000 > lines
sum=$(sha256sum < lines)

for c in gzip bzip2 xz lzma zstd; do
    cp lines "in-$c"
    $c "in-$c" 2>/dev/null
    case $c in gzip) s=gz ;; bzip2) s=bz2 ;; lzma) s=lzma ;; zstd) s=zst ;; *) s=$c ;; esac
    check "${c}_suffix" "$(ls "in-$c.$s" 2>&1)" "in-$c.$s"
    check "${c}_smaller" "$([ "$(wc -c < "in-$c.$s")" -lt 60000 ] && echo yes)" yes
    check "${c}_stdout" "$($c -dc < "in-$c.$s" | sha256sum)" "$sum"
    $c -d "in-$c.$s" 2>/dev/null
    check "${c}_back" "$(sha256sum < "in-$c")" "$sum"
done
check zcat "$(gzip -c lines | zcat | tail -n 1)" 20000
check xz_test "$(xz -c lines > t.xz; xz -t t.xz; echo $?)" 0
check gzip_corrupt "$(printf 'not gzip' | gzip -dc > /dev/null 2>&1; echo $?)" 1

mkdir -p tree/sub/deep
echo one > tree/a
echo two > tree/sub/b
echo three > tree/sub/deep/c
ln -s a tree/link
ln tree/a tree/hard
for z in "" -z -j -J --zstd; do
    rm -rf out; mkdir out
    tar -c $z -f t.tar tree
    tar -x -f t.tar -C out
    check "tar${z}_files" "$(cd out && find . | sort | tr '\n' ' ')" \
        ". ./tree ./tree/a ./tree/hard ./tree/link ./tree/sub ./tree/sub/b ./tree/sub/deep ./tree/sub/deep/c "
    check "tar${z}_link" "$(readlink out/tree/link)" a
    check "tar${z}_hard" "$(stat -c %h out/tree/hard)" 2
    check "tar${z}_data" "$(cat out/tree/sub/deep/c)" three
done
check tar_list "$(tar -tf t.tar | head -n 2 | tr '\n' ' ')" "tree/ tree/a "
check tar_auto "$(tar -caf t.tar.xz tree && xz -t t.tar.xz && tar -tf t.tar.xz | wc -l)" 8

rm -rf out; mkdir out
tar -cf t.tar tree
echo four > extra
tar -rf t.tar extra
check tar_append "$(tar -tf t.tar | tail -n 1)" extra
tar --delete -f t.tar tree/sub/b
check tar_delete "$(tar -tf t.tar | grep -c sub/b)" 0
tar -xf t.tar -C out --strip-components=3 tree/sub/deep/c
check tar_strip "$(cat out/c 2>&1)" three
check tar_missing "$(tar -xf t.tar -C out nothing 2>/dev/null; echo $?)" 2

truncate -s 64M sparse
printf 'head' | dd of=sparse conv=notrunc 2>/dev/null
printf 'tail' | dd of=sparse bs=1 seek=67108860 conv=notrunc 2>/dev/null
check sparse_blocks "$([ "$(stat -c %b sparse)" -lt 64 ] && echo yes)" yes
tar -cSf s.tar sparse
check sparse_small "$([ "$(wc -c < s.tar)" -lt 100000 ] && echo yes)" yes
rm -rf out; mkdir out
tar -xf s.tar -C out
check sparse_size "$(stat -c %s out/sparse)" 67108864
check sparse_data "$(cmp sparse out/sparse && echo same)" same

cd / && rm -rf "$d"
exit $fail
