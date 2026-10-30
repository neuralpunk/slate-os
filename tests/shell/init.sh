#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# slinit's service ordering (LSB headers) and its commands without init.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS init::$name"
    else
        echo "SLATE-TEST: FAIL init::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
svc() {
    # svc NAME REQUIRED SHOULD START-LEVELS
    cat > "/etc/init.d/$1" <<SCRIPT
#!/bin/sh
### BEGIN INIT INFO
# Provides:          $1
# Required-Start:    $2
# Should-Start:      $3
# Default-Start:     $4
# Default-Stop:      0 1 6
### END INIT INFO
echo "\$1 $1"
SCRIPT
    chmod 755 "/etc/init.d/$1"
}
mkdir -p /etc/init.d
svc web "net db" "" "2 3 4 5"
svc net "" "" "2 3 4 5"
svc db net log "3 5"
svc log "" "" "2 3 4 5"
svc late '$all' "" "3"
check order_3 "$(slinit --order 3 | grep -Ev "^(sshd|slate-brokerd|devd|seatd|netd|logd|slate-btd|slate-boxd|fstrim)$" | tr '\n' ' ')" "log net db web late "
check order_2 "$(slinit --order 2 | grep -Ev '^(sshd|slate-brokerd|devd|seatd|netd|logd|slate-btd|slate-boxd|fstrim)$' | tr '\n' ' ')" "log net web "
printf '#!/bin/sh\necho no header\n' > /etc/init.d/plain && chmod 755 /etc/init.d/plain
check no_header_ignored "$(slinit --order 3 | grep -c plain)" 0
rm -f /etc/init.d/web /etc/init.d/net /etc/init.d/db /etc/init.d/log /etc/init.d/late /etc/init.d/plain
check runlevel_without_init "$(runlevel; echo $?)" "unknown
1"
check service_without_init "$(service x start 2>&1 >/dev/null | grep -c 'cannot reach init')" 1
check telinit_usage "$(telinit 2>&1; echo $?)" "usage: telinit RUNLEVEL (0-6, S, Q)
2"
exit $fail
