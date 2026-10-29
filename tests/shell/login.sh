#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Users on Slate: passwd, su and login with /etc/shadow (SHA-512 crypt).
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS login::$name"
    else
        echo "SLATE-TEST: FAIL login::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}

echo 'tester:x:1000:1000:Test user:/home/tester:/bin/sh' >> /etc/passwd
echo 'tester:x:1000:' >> /etc/group
sed -i 's/^users:x:100:$/users:x:100:tester/' /etc/group
mkdir -p /home/tester && chown 1000:1000 /home/tester
# su and passwd ask the privilege broker (ADR 0032); slinit runs it on a
# real boot, and the test boot starts one here.
slate-brokerd & broker=$!
sleep 0.2
check not_setuid "$(stat -c %a /bin/su /bin/passwd | tr '\n' ' ')" "755 755 "
printf 'pw1\n' | passwd --stdin tester > /dev/null
check shadow_hash "$(grep -c '^tester:\$6\$' /etc/shadow)" 1
check shadow_mode "$(stat -c %a /etc/shadow)" 600
check su_as_root "$(su tester -c 'id -u')" 1000
check su_groups "$(su tester -c 'id -G')" "1000 100"
check su_login_env "$(su - tester -c 'echo $HOME $USER $LOGNAME; pwd')" "/home/tester tester tester
/home/tester"
check shadow_unreadable "$(su tester -c 'cat /etc/shadow 2>/dev/null; echo $?')" 1
printf 'rootpw\n' | passwd --stdin root > /dev/null
check su_wrong_password "$(su tester -c "printf 'bad\n' | su root -c 'echo in' 2>/dev/null; echo \$?")" 1
check su_right_password "$(su tester -c "printf 'rootpw\n' | su root -c 'id -u' 2>/dev/null")" 0
check passwd_own "$(su tester -c "printf 'pw1\npw2\n' | passwd --stdin > /dev/null 2>&1; echo \$?")" 0
check passwd_new_works "$(su tester -c "printf 'pw2\n' | su tester -c 'id -un' 2>/dev/null")" tester
check passwd_other_denied "$(su tester -c 'printf "x\n" | passwd --stdin root > /dev/null 2>&1; echo $?')" 1
check passwd_status "$(passwd -S tester | cut -d' ' -f2)" P
passwd -l tester > /dev/null
check passwd_lock "$(passwd -S tester | cut -d' ' -f2)" L
passwd -u tester > /dev/null
check security_log_granted "$(grep -c 'su: tester -> root: granted' /var/log/slate-security.log)" 1
check security_log_denied "$(grep -c 'su: tester -> root: denied (wrong password)' /var/log/slate-security.log)" 1
check security_log_passwd "$(grep -c 'passwd: tester for tester: changed' /var/log/slate-security.log)" 1
# Set-user-ID bits mean nothing to Slate programs.
cp /bin/coreutils /tmp/id && chmod 4755 /tmp/id
check setuid_ignored "$(su tester -c '/tmp/id -u')" 1000
rm /tmp/id
# Restricted introspection (ADR 0032): users see their own processes in
# /proc; the kernel log and scheduler dump are root's.
check proc_others_hidden "$(su tester -c "test -e /proc/$$/status && echo yes || echo no")" no
check proc_own_visible "$(su tester -c 'test -e /proc/$$/status && echo yes || echo no')" yes
check dmesg_root_only "$(su tester -c 'dmesg > /dev/null 2>&1; echo $?')" 1
check sched_root_only "$(su tester -c 'cat /proc/slate_sched > /dev/null 2>&1; echo $?')" 1
check login_preauth "$(printf 'id -un\npwd\n' | login -f tester 2>/dev/null | tail -n 2)" "tester
/home/tester"
check login_shell_is_login "$(printf 'echo $0\n' | login -f tester 2>/dev/null | tail -n 1)" "-sh"
check nologin "$(nologin; echo $?)" "This account is currently not available.
1"
# ADR 0119: an account without a password logs in without one at the
# machine but not from elsewhere, and nobody becomes it with su unless the
# policy says nopassword.
useradd -m nopw > /dev/null 2>&1 && passwd -d nopw > /dev/null
check login_empty_local "$(printf 'id -un\n' | login nopw 2>/dev/null | tail -n 1)" nopw
check login_empty_remote "$(printf '\n' | login -h far.example nopw 2>/dev/null | grep -c 'Login incorrect')" 1
check su_empty_refused "$(su tester -c "printf '\n' | su nopw -c 'id -un' 2>/dev/null; echo \$?")" 1
check su_empty_root "$(su nopw -c 'id -un')" nopw
# newgrp: members switch freely; others need the group's password
# (gshadow(5), set with gpasswd).
groupadd secret
secret=$(grep '^secret:' /etc/group | cut -d: -f3)
check newgrp_member "$(su tester -c "echo 'id -g' | newgrp users")" 100
check newgrp_not_member "$(su tester -c "echo 'id -g' | newgrp secret 2>/dev/null; echo \$?")" 1
printf 'gpw\ngpw\n' | gpasswd secret > /dev/null
check gshadow_mode "$(stat -c %a /etc/gshadow)" 600
check newgrp_password "$(su tester -c "printf 'gpw\nid -g\n' | newgrp secret 2>/dev/null")" "$secret"
check newgrp_wrong_password "$(su tester -c "printf 'bad\nid -g\n' | newgrp secret 2>/dev/null; echo \$?")" 1
check newgrp_back "$(su tester -c "echo 'id -g' | newgrp")" 1000
# sg runs a command with the group; a group's administrators (gpasswd
# -A, root's) add members and set or restrict its password through the
# broker (g281).
check sg_command "$(su tester -c "sg users -c 'id -g'")" 100
check sg_words "$(su tester -c 'sg users id -gn')" users
check gpasswd_A_root_only "$(su tester -c 'gpasswd -A tester secret' 2>&1)" "gpasswd: Permission denied."
gpasswd -A tester secret
check gpasswd_admins "$(grep '^secret:' /etc/gshadow | cut -d: -f3)" tester
check gpasswd_admin_add "$(su tester -c 'gpasswd -a nopw secret' 2>&1; grep '^secret:' /etc/group | cut -d: -f4)" "Adding user nopw to group secret
nopw"
su tester -c "printf 'g2\ng2\n' | gpasswd secret" > /dev/null 2>&1
check gpasswd_admin_password "$(su tester -c "printf 'g2\nid -g\n' | newgrp secret 2>/dev/null")" "$secret"
check gpasswd_admin_restrict "$(su tester -c 'gpasswd -R secret' 2>&1; grep '^secret:' /etc/gshadow | cut -d: -f2)" '!'
check gpasswd_not_admin "$(su nopw -c 'gpasswd -d tester secret' 2>&1)" "gpasswd: Permission denied."
gpasswd -r secret
check newgrp_password_removed "$(su tester -c "printf 'gpw\nid -g\n' | newgrp secret 2>/dev/null; echo \$?")" 1
groupdel secret
check gshadow_follows "$(grep -c '^secret:' /etc/gshadow)" 0
userdel -r nopw
kill $broker 2>/dev/null
exit $fail
