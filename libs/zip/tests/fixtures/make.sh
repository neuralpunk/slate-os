#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The zip reader's test archives (ADR 0106), made with Info-ZIP's zip
# from a small synthetic tree. Run in this directory; the results are
# committed.
set -e
work=$(mktemp -d)
mkdir -p "$work/tree/sub"
printf 'hello, zip\nhello, zip\nhello, zip\n' > "$work/tree/a.txt"
python3 -c "import sys; sys.stdout.buffer.write(bytes(i * 7 % 251 for i in range(4096)))" > "$work/tree/sub/b.bin"
ln -s a.txt "$work/tree/link"
: > "$work/tree/empty"
chmod 644 "$work/tree/a.txt" "$work/tree/sub/b.bin" "$work/tree/empty"
chmod 755 "$work/tree" "$work/tree/sub"
touch -d '2026-10-24 12:00:00' "$work/tree" "$work/tree/a.txt" "$work/tree/sub" "$work/tree/sub/b.bin" "$work/tree/empty"
here=$(pwd)
(cd "$work" && rm -f "$here/tree.zip" && zip -X -y -r "$here/tree.zip" tree/ tree/a.txt tree/sub/ tree/sub/b.bin tree/link tree/empty >/dev/null)
printf 'stored, not deflated\n' > "$work/s.txt"
(cd "$work" && rm -f "$here/stored.zip" && zip -X -0 "$here/stored.zip" s.txt >/dev/null)
rm -rf "$work"
