#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Network tools on QEMU's user-mode network (host at 10.0.2.2): Slate's
# ip, ping and ss (ADR 0052), BusyBox's others.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS net::$name"
    else
        echo "SLATE-TEST: FAIL net::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
check ping "$(ping -c 2 -W 2 10.0.2.2 2>&1 | grep -c 'bytes from 10.0.2.2')" 2
check ping_localhost "$(ping -c 1 -W 2 localhost 2>&1 | grep -c 'bytes from 127.0.0.1')" 1
# The TTL with each reply (IP_RECVTTL), a deadline, and an interface.
check ping_ttl "$(ping -c 1 -W 2 localhost 2>&1 | grep -c 'icmp_seq=1 ttl=64 time=')" 1
check ping_deadline "$(ping -w 1 -i 0.2 10.0.2.2 2>&1 | grep -c 'packets transmitted')" 1
check ping_interface "$(ping -c 1 -W 2 -I eth0 10.0.2.2 2>&1 | grep -c 'bytes from 10.0.2.2')" 1
check ifconfig "$(ifconfig eth0 | grep -c 'inet addr:10.0.2.15')" 1
check ifconfig_lo "$(ifconfig lo | grep -c '127.0.0.1')" 1
check route "$(route -n | grep -c '^0.0.0.0 *10.0.2.2')" 1
check resolv_conf "$(grep -c '^nameserver 10.0.2.3' /etc/resolv.conf)" 1
check hosts "$(grep -c localhost /etc/hosts)" 2
# iproute2-style tools over netlink.
check ip_addr "$(ip -4 addr show eth0 | grep -c 'inet 10.0.2.15/24')" 1
check ip_route "$(ip route | grep -c '^default via 10.0.2.2')" 1
check ip_link "$(ip link show lo | grep -c LOOPBACK)" 1
check ip_route_get "$(ip route get 192.0.2.1 | grep -c '^192.0.2.1 via 10.0.2.2 dev eth0 src 10.0.2.15')" 1
check ip_brief "$(ip -br link show lo | grep -c '^lo  .*<LOOPBACK')" 1
# Packet sockets (ADR 0049): arping (ARP over a cooked packet socket) and
# udhcpc (DHCP over one, with a socket filter); the ARP table.
check arping "$(arping -c 1 -w 3 -I eth0 10.0.2.2 2>&1 | grep -c 'Received 1 response')" 1
check udhcpc "$(udhcpc -i eth0 -n -q -t 3 -T 2 -s /bin/true 2>&1 | grep -c 'lease of 10.0.2.15 obtained')" 1
check proc_net_arp "$(grep -c '^10.0.2.2 .* eth0$' /proc/net/arp)" 1
check ip_neigh "$(ip neigh show dev eth0 | grep -c '^10.0.2.2 lladdr')" 1
# IPv6 (ADR 0050): QEMU's router gives fec0::/64; its host is fec0::2.
for i in $(seq 100); do grep -q '^fec0.* eth0$' /proc/net/if_inet6 && break; sleep 0.1; done
check ping6 "$(ping6 -c 1 -W 3 fec0::2 2>&1 | grep -c 'bytes from fec0::2')" 1
check ip6_addr "$(ip -6 addr show dev eth0 | grep -c 'inet6 fec0::5054:ff:fe12:3456/64')" 1
check ip6_route "$(ip -6 route | grep -c '^default via fe80::')" 1
check ip6_link_local "$(ip -6 addr show dev eth0 | grep -c 'inet6 fe80::5054:ff:fe12:3456/64 scope link')" 1
# HTTP from the host's server with wget, and nc over loopback.
arg() { tr ' ' '\n' < /proc/cmdline | grep "^$1=" | cut -d= -f2; }
wget -q -O /tmp/download "http://10.0.2.2:$(arg slate.http)/file"
check wget "$(md5sum /tmp/download | cut -d' ' -f1)" "$(arg slate.httpmd5)"
rm -f /tmp/download
wget -q -O /tmp/download "http://[fec0::2]:$(arg slate.http)/file"
check wget6 "$(md5sum /tmp/download | cut -d' ' -f1)" "$(arg slate.httpmd5)"
rm -f /tmp/download
# Slate's fetch (ADR 0052): IPv4, IPv6, a redirect, a chunked body.
fetched() {
    fetch -q -o /tmp/download "$1"
    md5sum /tmp/download | cut -d' ' -f1
    rm -f /tmp/download
}
web=$(arg slate.http)
check fetch "$(fetched "http://10.0.2.2:$web/file")" "$(arg slate.httpmd5)"
check fetch6 "$(fetched "http://[fec0::2]:$web/file")" "$(arg slate.httpmd5)"
check fetch_redirect "$(fetched "http://10.0.2.2:$web/redirect")" "$(arg slate.httpmd5)"
check fetch_chunked "$(fetched "http://10.0.2.2:$web/chunked")" "$(arg slate.httpmd5)"
check fetch_stdout "$(fetch -q "http://10.0.2.2:$(arg slate.http)/chunked" | md5sum | cut -d' ' -f1)" "$(arg slate.httpmd5)"
# -c continues a file partly there (a Range request), and leaves a whole
# one as it is; -P shows the progress.
fetch -q -o /tmp/whole "http://10.0.2.2:$web/file"
head -c 1000 /tmp/whole > /tmp/part
check fetch_continue "$(fetch -q -c -o /tmp/part "http://10.0.2.2:$web/file"; md5sum /tmp/part | cut -d' ' -f1)" "$(arg slate.httpmd5)"
check fetch_complete "$(fetch -c -o /tmp/part "http://10.0.2.2:$web/file" 2>&1)" "fetch: http://10.0.2.2:$web/file: /tmp/part is complete already"
check fetch_progress "$(fetch -q -P -o /tmp/part "http://10.0.2.2:$web/file" 2>&1 | tr '\r' '\n' | tail -1 | grep -c 'bytes (100%)$')" 1
rm -f /tmp/whole /tmp/part
# https (ADR 0072) to a server that speaks plain HTTP: refused as not TLS
# (quarry.sh fetches over real HTTPS).
check fetch_https "$(fetch https://10.0.2.2:$web/file 2>&1; echo rc=$?)" "fetch: https://10.0.2.2:$web/file: TLS: the server closed the connection during the handshake
rc=1"
nc -l -p 4242 > /tmp/nc.out &
sleep 0.3
echo "through nc" | nc 127.0.0.1 4242
wait
check nc_loopback "$(cat /tmp/nc.out)" "through nc"
exit $fail
