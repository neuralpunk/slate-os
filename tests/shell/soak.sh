# SPDX-License-Identifier: MIT OR Apache-2.0
# The soak run's load (ADR 0047; `cargo xtask soak`): file churn on the
# SlateFS root, process churn, the threads/events/memory test programs in
# turn, HTTP downloads from the host, for MINUTES minutes. Every minute a
# SOAK-SAMPLE line gives the memory in use (KiB, without the page cache),
# the kernel heap (KiB) and the number of processes; the idle state is
# sampled before and after. Failures of the programs are listed in
# /tmp/soak-fail.
#   sh /test/soak.sh MINUTES HTTP_PORT [WORKERS [PROGRAMS...]]
# WORKERS picks some of: files procs programs net (all by default);
# PROGRAMS which test programs the programs worker runs.
minutes=$1
port=$2
workers=${3:-files procs programs net}
list="threads events unix mallocfork forkthreads cowstale teardown fpu locks resources"
if [ $# -gt 3 ]; then
    shift 3
    list="$*"
fi
rm -f /tmp/soak-stop /tmp/soak-fail
touch /tmp/soak-fail
mkdir -p /var/soak

sample() {
    used=$(awk '/^MemTotal:/ {t=$2} /^MemFree:/ {f=$2} /^Cached:/ {c=$2} END {print t-f-c}' /proc/meminfo)
    heap=$(awk '/^Slab:/ {print $2}' /proc/meminfo)
    procs=$(ls /proc | grep -c '^[0-9]')
    echo "SOAK-SAMPLE $1 used=$used heap=$heap procs=$procs"
    grep -E '^(heap objects|objects alive|cached dentries)' /proc/slate_sched
}

files() {
    while [ ! -e /tmp/soak-stop ]; do
        for i in 1 2 3 4; do
            dd if=/dev/urandom of=/var/soak/f$i bs=64k count=16 2>/dev/null
        done
        a=$(cat /var/soak/f1 /var/soak/f2 | md5sum)
        b=$(cat /var/soak/f1 /var/soak/f2 | md5sum)
        [ "$a" = "$b" ] || echo "files: reads disagree" >> /tmp/soak-fail
        mkdir -p /var/soak/tree
        cp -r /etc /var/soak/tree/ 2>/dev/null
        rm -rf /var/soak/tree /var/soak/f*
        sync
    done
}

procs() {
    while [ ! -e /tmp/soak-stop ]; do
        i=0
        while [ $i -lt 50 ]; do
            /test/hello > /dev/null || echo "procs: hello failed" >> /tmp/soak-fail
            i=$((i + 1))
        done
        r=$(echo soak | tr a-z A-Z | sed 's/O/0/g')
        [ "$r" = "S0AK" ] || echo "procs: pipeline gave $r" >> /tmp/soak-fail
    done
}

programs() {
    while [ ! -e /tmp/soak-stop ]; do
        for p in $list; do
            [ -e /tmp/soak-stop ] && break
            [ -x /test/$p ] || { echo "programs: no /test/$p" >> /tmp/soak-fail; sleep 10; continue; }
            /test/$p > /tmp/soak-$p.out 2>&1 || {
                echo "programs: $p failed" >> /tmp/soak-fail
                grep FAIL /tmp/soak-$p.out | head -3 >> /tmp/soak-fail
            }
            rm -f /tmp/soak-$p.out
        done
    done
}

net() {
    while [ ! -e /tmp/soak-stop ]; do
        wget -q -O /dev/null http://10.0.2.2:$port/big || echo "net: download failed" >> /tmp/soak-fail
        sleep 1
    done
}

sample idle-before
ls /proc | grep "^[0-9]" | while read p; do echo "before: $p $(cat /proc/$p/comm 2>/dev/null)"; done
for w in $workers; do
    $w &
done
m=0
while [ $m -lt $minutes ]; do
    sleep 60
    m=$((m + 1))
    sample minute-$m
done
touch /tmp/soak-stop
wait
rm -rf /var/soak
sync
# Past TCP's TIME-WAIT (30 s), so closed connections are gone too.
sleep 35
sample idle-after
ls /proc | grep '^[0-9]' | while read p; do echo "left: $p $(cat /proc/$p/comm 2>/dev/null)"; done
echo "SOAK-DONE fails=$(wc -l < /tmp/soak-fail)"
sort /tmp/soak-fail | uniq -c | sort -rn | head -20
