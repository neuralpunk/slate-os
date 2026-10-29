#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# quarry on Slate (ADR 0025): signed repositories over HTTP from xtask,
# installing with dependencies, upgrading, removing, verifying, and
# refusing what is unsigned, untrusted or tampered with.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS quarry::$name"
    else
        echo "SLATE-TEST: FAIL quarry::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
has() {
    case "$2" in
        *"$3"*) echo "SLATE-TEST: PASS quarry::$1" ;;
        *) echo "SLATE-TEST: FAIL quarry::$1 (got '$2', want something with '$3')"; fail=$((fail + 1)) ;;
    esac
}
port=$(sed -n 's/.*slate\.repo=\([0-9]*\).*/\1/p' /proc/cmdline)
repo() { echo "main http://10.0.2.2:$port/$1" > /etc/quarry/repos; }

# Host names come from /etc/hosts (and DNS, checked by `cargo xtask accept`).
echo "10.0.2.2 slate-repo" >> /etc/hosts
echo "main http://slate-repo:$port/v1" > /etc/quarry/repos
check update_by_name "$(quarry update 2>&1)" "main: 3 packages"
# Over HTTPS (ADR 0053), from xtask's server with a test authority this
# image trusts: the index, a package, and fetch; a certificate for
# another name is refused.
tport=$(sed -n 's/.*slate\.repo_tls=\([0-9]*\).*/\1/p' /proc/cmdline)
if [ -n "$tport" ]; then
    echo "main https://slate-repo:$tport/v1" > /etc/quarry/repos
    check update_https "$(quarry update 2>&1)" "main: 3 packages"
    check install_https "$(quarry install libgreet 2>&1)" "installing libgreet-1"
    quarry remove libgreet > /dev/null 2>&1
    check fetch_https "$(fetch -q https://slate-repo:$tport/v1/INDEX | head -1)" "quarry-index 1"
    echo "10.0.2.2 other-repo" >> /etc/hosts
    has https_wrong_name "$(fetch -q https://other-repo:$tport/v1/INDEX 2>&1)" "the certificate is for another name"
fi
repo v1
check update "$(quarry update 2>&1)" "main: 3 packages"
check search "$(quarry search hello 2>&1 | grep "^hello ")" "hello 1.0 - Says hello"
check install_with_deps "$(quarry install hello 2>&1)" "installing libgreet-1
installing hello-1.0"
check run "$(hello)" "hello 1.0: greetings"
check symlink "$(hi)" "hello 1.0: greetings"
check list "$(quarry list | grep -v '^slate-\|^ca-certificates ' | cut -d' ' -f1,2 | tr '\n' ,)" "hello 1.0,libgreet 1,"
check files "$(quarry files libgreet | grep text)" "/usr/share/greet/text"
quarry install qhello > /dev/null 2>&1
check linux_binary "$(qhello)" "qhello: a Linux binary from quarry"
has info_abi "$(quarry info qhello)" "abi: linux"
check verify "$(quarry verify hello libgreet qhello 2>&1; echo rc=$?)" "rc=0"
check remove_needed "$(quarry remove libgreet 2>&1; echo rc=$?)" "quarry: libgreet is needed by hello
rc=1"

# The administrator's change to a configuration file survives upgrades
# (ADR 0069); the package's version goes beside it.
echo "greeting = howdy" > /etc/hello.conf
repo v2
quarry update > /dev/null 2>&1
check upgrade "$(quarry upgrade 2>&1 | grep upgrading)" "upgrading hello 1.0 -> 1.1"
check config_kept "$(cat /etc/hello.conf)" "greeting = howdy"
check config_new "$(grep -c wave /etc/hello.conf.quarry-new)" 1
check config_changed_ok "$(quarry verify hello 2>&1; echo rc=$?)" "hello: /etc/hello.conf: changed (configuration)
rc=0"
check run_upgraded "$(hello)" "hello 1.1: greetings"
check old_file_removed "$(test -e /usr/bin/hi; echo $?)" 1
check new_file "$(cat /usr/share/doc/hello/NEWS)" "1.1: no more hi"
check up_to_date "$(quarry upgrade 2>&1)" "everything is up to date"
# The system image is read-only to root (ADR 0090): an installed program
# cannot be changed behind quarry's back.
check image_refuses_root "$(sh -c 'echo extra >> /usr/bin/hello' 2>&1 | grep -c 'Read-only')" 1
check verify_clean "$(quarry verify hello 2>&1 | grep -c modified)" 0
check remove "$(quarry remove hello qhello 2>&1 | tr '\n' ,)" "removing hello-1.1,kept /etc/hello.conf (changed here),removing qhello-1.0,no longer needed: libgreet (quarry autoremove removes them),"
check autoremove "$(quarry autoremove 2>&1)" "removing libgreet-1"
rm -f /etc/hello.conf /etc/hello.conf.quarry-new
check removed "$(test -e /usr/bin/hello || test -e /usr/share/greet/text || test -e /usr/share/doc/hello || echo gone)" gone
check nothing_installed "$(quarry list | grep -v '^ca-certificates ' | grep -cv '^slate-')" 0

# Refused: an unsigned package, one signed by an untrusted key, a package
# that does not match its index, and an index signed by an untrusted key.
check unsigned "$(quarry install /test/quarry/unsigned.qpk 2>&1; echo rc=$?)" "quarry: /test/quarry/unsigned.qpk: not signed; refusing it
rc=1"
has untrusted "$(quarry install /test/quarry/untrusted.qpk 2>&1; echo rc=$?)" "untrusted key"
repo bad
quarry update > /dev/null 2>&1
has tampered "$(quarry install libgreet 2>&1; echo rc=$?)" "does not match the index"
repo forged
has forged_index "$(quarry update 2>&1; echo rc=$?)" "index rejected: signed by an untrusted key"
check nothing_installed_after "$(quarry list | grep -v '^ca-certificates ' | grep -cv '^slate-')" 0

# Per-app permissions (ADR 0130): a package declaring a permission Slate
# doesn't know is refused; the same unsigned native program as qapp
# (network) and qbare (nothing) runs in the Slate domain, confined to its
# manifest, as is what it runs; the shell itself is not.
repo apps
quarry update > /dev/null 2>&1
has unknown_permission "$(quarry install qbad 2>&1; echo rc=$?)" "unknown permission 'teleport'"
quarry install qapp qbare > /dev/null 2>&1
check registry "$(grep '^/usr/bin/q' /usr/lib/quarry/apps | sort | tr '\n' ,)" "/usr/bin/qapp network,/usr/bin/qbare none,"
echo secret > /root/qsecret
check app_network "$(qapp)" "domain=slate permissions=network inet=ok home=denied gpu=denied child-home=denied"
check app_nothing "$(qbare)" "domain=slate permissions=none inet=denied home=denied gpu=denied child-home=denied"
check shell_unconfined "$(cat /root/qsecret)" "secret"
quarry remove qapp qbare > /dev/null 2>&1
check registry_cleared "$(grep -c '^/usr/bin/q' /usr/lib/quarry/apps)" 0
rm -f /root/qsecret
exit $fail
