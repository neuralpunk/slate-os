#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# seatd (ADR 0033): slinit runs it on a real boot; the test boot starts
# one here and /test/seat speaks its protocol.
mkdir -p /run
seatd & seatd=$!
for i in $(seq 50); do [ -S /run/seatd.sock ] && break; sleep 0.1; done
/test/seat
status=$?
kill $seatd
wait $seatd 2>/dev/null
exit $status
