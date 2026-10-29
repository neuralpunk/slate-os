#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# The fixture tests/difftest/cases.txt runs in (fixed times, no
# host-specific ownership in the outputs compared).
set -e
mkdir -p d/sub d/empty tree/a/b
printf 'hello\n' > d/a
printf 'b\na\nc\nb\n10\n9\n' > d/s
printf 'x y  z\n\tindented\n' > d/w
printf 'no newline' > d/nonl
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\n' > d/lines
printf 'k1:v1:x\nk2:v2:y\nk3::z\n' > d/colon
printf '3 apple\n1 pear\n2 Banana\n10 fig\n' > d/fruit
printf 'one\ntwo\nthree\n' > d/v1
printf 'one\n2\nthree\nfour\n' > d/v2
printf 'a\0b\0' > d/nul
printf 'hello world\n\001\377abcdefghijklmnopqrstuvwxyz\n' > d/bin
printf '%053d' 0 > d/zeros
printf 'a 1\nb 2\nc 3\nc 33\ne 5\n' > d/j1
printf 'a x\nc y\nc yy\nd z\ne w q\n' > d/j2
printf 'b 1\na 2\n' > d/unsorted
ln -s a d/link
ln -s missing d/dangling
: > tree/a/b/f
touch -d '2020-01-02 03:04:05' d/a d/s d/w d/nonl d/lines d/colon d/fruit d/v1 d/v2 d/nul d/bin d/zeros d/j1 d/j2 d/unsorted tree/a/b/f
# Archives made by the host's GNU gzip and tar, for gzip and tar to read.
gzip -9 -c d/lines > lines.gz
gzip -1 -c d/fruit > fruit.gz
bzip2 -9 -c d/lines > lines.bz2
xz -c d/lines > lines.xz
xz -c -C sha256 d/fruit > fruit.xz
xz --format=lzma -c d/lines > lines.lzma
zstd -q -c d/lines > lines.zst
zstd -q -19 -c d/fruit > fruit.zst
tar --sort=name --owner=root:0 --group=root:0 --mtime='2020-01-02 03:04:05' -cf host.tar d tree
gzip -c host.tar > host.tgz
bzip2 -c host.tar > host.tbz
xz -c host.tar > host.txz
zstd -q -c host.tar > host.tzst
# x86 long doubles for od -tfL (ADR 0148).
printf '\000\000\000\000\000\000\000\200\377\077\000\000\000\000\000\000\000\000\000\000\000\000\000\300\000\300\000\000\000\000\000\000\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\200\377\177\000\000\000\000\000\000\000\000\000\000\000\000\000\200\377\377\000\000\000\000\000\000\001\000\000\000\000\000\000\200\377\177\000\000\000\000\000\000\377\377\377\377\377\377\377\377\365\077\000\000\000\000\000\000\211\147\105\043\001\357\315\253\143\100\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\200\000\000\000\000\000\000\377\377\377\377\377\377\377\377\177\176\000\000\000\000\000\000\000\000\000\000\000\000\000\200\001\000\000\000\000\000\000\000\315\314\314\314\314\314\314\314\376\077\000\000\000\000\000\000\001\000\000\000\000\000\000\200\002\300\000\000\000\000\000\000\064\022\000\000\000\000\000\000\005\000\000\000\000\000\000\000\377\377\377\377\377\377\377\377\076\100\000\000\000\000\000\000' > d/ld
printf '\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020' > d/e16
