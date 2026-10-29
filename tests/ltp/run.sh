# SPDX-License-Identifier: MIT OR Apache-2.0
# Runs the LTP subset (ADR 0047) put in /test/ltp by xtask: one line per
# test, and the number of failures as the exit status. LTP exits 0 when
# every check passed and 32 when it could not run (TCONF): a test in the
# subset must pass, so both a failure and a skip count against it.
export TMPDIR=/tmp/ltp
# Some tests run helpers of their own by name.
export PATH=/test/ltp:$PATH
mkdir -p $TMPDIR
fails=0
for t in $(cat /test/ltp/LIST); do
    /test/ltp/$t > /tmp/ltp-$t.out 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "SLATE-TEST: PASS ltp::$t"
    else
        echo "SLATE-TEST: FAIL ltp::$t (exit $rc)"
        grep -E 'TFAIL|TBROK|TCONF|TWARN' /tmp/ltp-$t.out | head -5
        fails=$((fails + 1))
    fi
    rm -f /tmp/ltp-$t.out
done
echo "ltp: $fails failed"
exit $fails
