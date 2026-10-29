#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# slate-firewall (ADR 0134): the kernel's default-deny inbound firewall is
# on with nothing open (rc.sysinit hasn't run here); `load` opens what
# /etc/slate/firewall lists; `allow` and `deny` change the live firewall
# and the file; `off` and `on` take it away and bring it back.
fail=0
has() {
    case "$2" in
        *"$3"*) echo "SLATE-TEST: PASS firewall::$1" ;;
        *) echo "SLATE-TEST: FAIL firewall::$1 (got '$2', want something with '$3')"; fail=$((fail + 1)) ;;
    esac
}
lacks() {
    case "$2" in
        *"$3"*) echo "SLATE-TEST: FAIL firewall::$1 (got '$2', want nothing with '$3')"; fail=$((fail + 1)) ;;
        *) echo "SLATE-TEST: PASS firewall::$1" ;;
    esac
}
has on_at_boot "$(slate-firewall 2>&1)" "open tcp: none"
has status_on "$(slate-firewall status 2>&1)" "firewall: on"
slate-firewall load
has loaded "$(slate-firewall status 2>&1)" "open tcp: 22"
# Settings reads whether it is on from what slate-firewall recorded.
has recorded_on "$(cat /run/slate-firewall)" "on"
slate-firewall allow udp 5353 9999
has allowed "$(slate-firewall status 2>&1)" "open udp: 5353 9999"
has allowed_saved "$(cat /etc/slate/firewall)" "allow udp 9999"
slate-firewall deny udp 9999
has denied "$(slate-firewall status 2>&1)" "open udp: 5353"
lacks denied_saved "$(cat /etc/slate/firewall)" "allow udp 9999"
has bad_port "$(slate-firewall allow tcp 70000 2>&1)" "not a port"
slate-firewall off
has off "$(slate-firewall status 2>&1)" "firewall: off"
has recorded_off "$(cat /run/slate-firewall)" "off"
slate-firewall on
has on_again "$(slate-firewall status 2>&1)" "open tcp: 22"
has recorded_on_again "$(cat /run/slate-firewall)" "on"
slate-firewall deny udp 5353
exit $fail
