# SPDX-License-Identifier: MIT OR Apache-2.0
# $! of an asynchronous pipeline is its last command's process (ADR 0145).
true | sleep 0.3 &
cat /proc/$!/comm
wait
echo start | (read x; echo "got $x") &
wait $!
echo "status $?"
