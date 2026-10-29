#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Account administration (M21 phase 2, ADR 0057): useradd, usermod,
# userdel, groupadd, groupmod, groupdel, gpasswd, chpasswd, chage, chsh,
# passwd's ageing options, and password ageing at su.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS accounts::$name"
    else
        echo "SLATE-TEST: FAIL accounts::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
slate-brokerd & broker=$!
sleep 0.2

check useradd "$(useradd -G wheel -c 'Bob B' bob; echo $?)" 0
check passwd_line "$(grep '^bob:' /etc/passwd | cut -d: -f5-7)" "Bob B:/home/bob:/bin/sh"
uid=$(id -u bob)
check own_group "$(id -gn bob)" bob
check own_gid "$(id -g bob)" "$uid"
check wheel_member "$(id -Gn bob | tr ' ' '\n' | grep -c '^wheel$')" 1
check home_made "$(stat -c '%u %a' /home/bob)" "$uid 700"
check shadow_locked "$(grep '^bob:' /etc/shadow | cut -d: -f2)" '!'
check shadow_ageing "$(grep '^bob:' /etc/shadow | cut -d: -f4-6)" "0:99999:7"
check useradd_exists "$(useradd bob 2>&1; echo $?)" "useradd: user 'bob' already exists
9"
check useradd_bad_name "$(useradd 'Bad:Name' 2>/dev/null; echo $?)" 3
check useradd_bad_group "$(useradd -g nosuch carl 2>&1; echo $?)" "useradd: group 'nosuch' does not exist
6"
check useradd_system "$(useradd -r svc && id -u svc)" 999
check system_no_home "$(test -e /home/svc && echo yes || echo no)" no
check useradd_defaults "$(useradd -D | grep -c '^SHELL=/bin/sh$')" 1
# A mail spool when /etc/default/useradd asks for one (ADR 0143).
check useradd_no_spool "$(useradd -D | grep CREATE_MAIL_SPOOL)" CREATE_MAIL_SPOOL=no
cp /etc/default/useradd /tmp/useradd.saved
echo CREATE_MAIL_SPOOL=yes >> /etc/default/useradd
mkdir -p /var/spool/mail
check useradd_spool "$(useradd spooly && stat -c '%U %a %s' /var/spool/mail/spooly)" "spooly 600 0"
check userdel_spool "$(userdel -r spooly; test -e /var/spool/mail/spooly && echo kept || echo gone)" gone
cp /tmp/useradd.saved /etc/default/useradd

printf 'bob:bobpw\n' | chpasswd
check chpasswd "$(grep -c '^bob:\$6\$' /etc/shadow)" 1
# passwd -S's seven fields (passwd(1)), and -a for everyone.
check passwd_status_fields "$(passwd -S bob | cut -d' ' -f1,2,4-)" "bob P 0 99999 7 -1"
check passwd_status_date "$(passwd -S bob | cut -d' ' -f3)" "$(date -u +%F)"
check passwd_status_all "$(passwd -Sa | grep -c '^root ')" 1
check su_to_bob "$(su bob -c 'id -un')" bob
check chage_list "$(chage -l bob | grep 'Maximum number' | cut -d: -f2 | tr -d ' ')" 99999
chage -M 30 -W 5 bob
check chage_set "$(grep '^bob:' /etc/shadow | cut -d: -f5,6)" "30:5"
chage -E 2000-01-01 bob
check expired_su "$(su tester -c "printf 'bobpw\n' | su bob -c 'id -un' 2>&1")" "su: Your account has expired; please contact your system administrator."
chage -E -1 bob
passwd -e bob > /dev/null
check passwd_expire "$(grep '^bob:' /etc/shadow | cut -d: -f3)" 0
check must_change_su "$(su tester -c "printf 'bobpw\n' | su bob -c 'id -un' 2>&1")" "su: the target's password has expired"
passwd -x 99999 -n 1 bob > /dev/null
check passwd_ageing "$(grep '^bob:' /etc/shadow | cut -d: -f4,5)" "1:99999"
printf 'bob:bobpw\n' | chpasswd
check su_after_change "$(su tester -c "printf 'bobpw\n' | su bob -c 'id -un' 2>&1")" bob

# chsh: root for anyone, users their own through the broker.
check chsh_root "$(chsh -s /bin/chalk bob; grep '^bob:' /etc/passwd | cut -d: -f7)" /bin/chalk
check chsh_user "$(su bob -c "printf 'bobpw\n' | chsh -s /bin/sh" 2>&1; grep '^bob:' /etc/passwd | cut -d: -f7)" /bin/sh
check chsh_bad_shell "$(su bob -c "printf 'bobpw\n' | chsh -s /bin/nosuch" 2>&1)" "chsh: /bin/nosuch is an invalid shell"
check chsh_other "$(su bob -c "printf 'bobpw\n' | chsh -s /bin/sh root" 2>&1)" "chsh: Permission denied."

# Groups.
check groupadd "$(groupadd -g 2500 devs; grep '^devs:' /etc/group)" "devs:x:2500:"
check groupadd_exists "$(groupadd devs 2>/dev/null; echo $?)" 9
check groupadd_force "$(groupadd -f devs; echo $?)" 0
check gpasswd_add "$(gpasswd -a bob devs; grep '^devs:' /etc/group)" "Adding user bob to group devs
devs:x:2500:bob"
check usermod_append "$(usermod -aG users bob; id -Gn bob | tr ' ' '\n' | sort | tr '\n' ' ')" "bob devs users wheel "
check usermod_groups "$(usermod -G devs bob; id -Gn bob | tr ' ' '\n' | sort | tr '\n' ' ')" "bob devs "
check groupmod "$(groupmod -n developers -g 2600 devs; grep '^developers:' /etc/group)" "developers:x:2600:bob"
check groupdel_primary "$(groupdel bob 2>&1; echo $?)" "groupdel: cannot remove the primary group of user 'bob'
8"
check usermod_lock "$(usermod -L bob; grep '^bob:' /etc/shadow | cut -c5)" '!'
usermod -U bob
check usermod_rename "$(usermod -l robert -c Robert bob; grep '^robert:' /etc/passwd | cut -d: -f5; grep -c '^robert:' /etc/shadow; grep '^developers:' /etc/group)" "Robert
1
developers:x:2600:robert"
check usermod_not_root "$(su tester -c 'usermod -s /bin/sh robert' 2>&1; echo $?)" "usermod: Permission denied.
1"
check userdel "$(userdel -r robert; grep -c '^robert:' /etc/passwd /etc/shadow | tr '\n' ' '; test -e /home/bob && echo home || echo gone)" "/etc/passwd:0 /etc/shadow:0 gone"
# A renamed user's group keeps its old name, so it stays (as with
# shadow-utils); one named after the user goes with it.
check userdel_renamed_group_kept "$(grep -c '^bob:' /etc/group)" 1
groupdel bob
check userdel_group_gone "$(useradd carol && userdel carol; grep -c '^carol:' /etc/group)" 0
check userdel_member_gone "$(grep '^developers:' /etc/group)" "developers:x:2600:"
check groupdel "$(groupdel developers; grep -c '^developers:' /etc/group)" 0
check userdel_missing "$(userdel nosuch 2>&1; echo $?)" "userdel: user 'nosuch' does not exist
6"
userdel svc

# sudo through the broker (ADR 0058): wheel members with their own
# password, remembered for the terminal session.
useradd -G wheel ann && printf 'ann:annpw\n' | chpasswd
check sudo_password "$(su ann -c "printf 'annpw\n' | sudo -S id -u" 2>/dev/null)" 0
check sudo_remembered "$(su ann -c 'sudo -n id -u' 2>&1)" 0
check sudo_as_user "$(su ann -c 'sudo -n -u tester id -un' 2>&1)" tester
check sudo_env "$(su ann -c 'sudo -n sh -c "echo \$SUDO_USER \$HOME \$USER"' 2>&1)" "ann /root root"
check sudo_list "$(su ann -c 'sudo -l' | tail -1)" "    (ALL : ALL) ALL"
check sudo_forget "$(su ann -c 'sudo -k; sudo -n id -u' 2>&1; echo $?)" "sudo: a password is required
1"
check sudo_wrong "$(su ann -c "printf 'x\ny\nz\n' | sudo -S id -u" 2>&1 | tail -1)" "sudo: 3 incorrect password attempts"
check sudo_not_allowed "$(su tester -c 'sudo -n id -u' 2>&1)" "sudo: tester is not allowed to run commands as root"
check sudo_log "$(grep -c 'run: ann -> root: id -u: granted' /var/log/slate-security.log)" 2
check sudo_not_setuid "$(stat -c %a /bin/sudo)" 755
# ADR 0142: a group (-g), descriptors closed from 3 (-C moves that),
# the background (-b).
su ann -c "printf 'annpw\n' | sudo -S -v" 2>/dev/null
check sudo_group "$(su ann -c 'sudo -n -g users sh -c "id -un; id -gn"' 2>&1 | tr '\n' ' ')" "ann users "
check sudo_group_user "$(su ann -c 'sudo -n -u tester -g wheel id -gn' 2>&1)" wheel
check sudo_closes "$(su ann -c 'exec 5</etc/passwd; sudo -n sh -c "test -e /proc/self/fd/5 && echo open || echo closed"')" closed
check sudo_close_from "$(su ann -c 'exec 5</etc/passwd; sudo -n -C 6 sh -c "test -e /proc/self/fd/5 && echo open || echo closed"')" open
check sudo_close_bad "$(su ann -c 'sudo -n -C 2 true' 2>&1)" "sudo: the argument to -C must be a number greater than or equal to 3"
rm -f /tmp/sudo_bg
su ann -c "sudo -n -b sh -c 'id -u > /tmp/sudo_bg'"
n=0; while [ ! -s /tmp/sudo_bg ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
check sudo_background "$(cat /tmp/sudo_bg)" 0
# Rules that name commands and files (ADR 0142).
cp /etc/slate/broker.conf /tmp/broker.conf.saved
cat >> /etc/slate/broker.conf <<'POLICY'
run tester root nopassword /bin/id -u
run tester root nopassword /sbin/
run tester root nopassword sudoedit /etc/sudo-test.conf
run tester root nopassword sudoedit /etc/sudo-link
run tester root nopassword sudoedit /home/tester/notes
POLICY
check sudo_cmd_allowed "$(su tester -c 'sudo -n id -u' 2>&1)" 0
check sudo_cmd_args "$(su tester -c 'sudo -n id -g' 2>&1; echo $?)" "sudo: tester is not allowed to run id -g as root
1"
check sudo_cmd_other "$(su tester -c 'sudo -n /bin/cat /etc/shadow' 2>&1 | head -1)" "sudo: tester is not allowed to run /bin/cat /etc/shadow as root"
check sudo_cmd_dir "$(su tester -c 'sudo -n groupdel nosuch' 2>&1)" "groupdel: group 'nosuch' does not exist"
check sudo_list_cmd "$(su tester -c 'sudo -l id -u'; su tester -c 'sudo -l id -g'; echo $?)" "/bin/id -u
1"
check sudo_list_rules "$(su tester -c 'sudo -l' | grep -c 'NOPASSWD: sudoedit')" 3
printf 'old\n' > /etc/sudo-test.conf
printf '#!/bin/sh\nid -un > "$1"\n' > /tmp/sudo-ed.sh
chmod 755 /tmp/sudo-ed.sh
check sudoedit "$(su tester -c 'SUDO_EDITOR=/tmp/sudo-ed.sh sudoedit /etc/sudo-test.conf' 2>&1; cat /etc/sudo-test.conf; stat -c %U /etc/sudo-test.conf)" "tester
root"
check sudoedit_flag "$(su tester -c 'cd /etc && EDITOR=/bin/true sudo -e sudo-test.conf' 2>&1)" "sudoedit: /etc/sudo-test.conf unchanged"
check sudoedit_no_copies "$(ls /var/tmp /tmp 2>/dev/null | grep -c 'sudo-test.conf\.')" 0
check sudoedit_other "$(su tester -c 'EDITOR=/bin/true sudoedit /etc/passwd' 2>&1)" "sudo: tester is not allowed to run sudoedit /etc/passwd as root"
ln -s /etc/shadow /etc/sudo-link
check sudoedit_link "$(su tester -c 'EDITOR=/bin/true sudoedit /etc/sudo-link' 2>&1)" "sudo: /etc/sudo-link: editing symbolic links is not permitted"
check sudoedit_writable_dir "$(su tester -c 'EDITOR=/bin/true sudoedit /home/tester/notes' 2>&1)" "sudo: /home/tester/notes: editing files in a writable directory is not permitted"
# Lists, aliases, tags, defaults, the options and I/O logs (ADR 0159).
cat >> /etc/slate/broker.conf <<'POLICY'
commands SHOW = /bin/echo, /bin/printf
users TESTERS = tester
run TESTERS root nopassword SHOW, /bin/true ""
run TESTERS nobody,tester nopassword setenv /bin/env
POLICY
check sudo_alias "$(su tester -c 'sudo -n echo listed' 2>&1)" listed
check sudo_list_exact "$(su tester -c 'sudo -n true x' 2>&1)" "sudo: tester is not allowed to run true x as root"
check sudo_newline "$(su tester -c "sudo -n printf '%s|' 'a
b'" 2>&1)" "a
b|"
check sudo_newline_logged "$(grep -cF 'printf %s| a\nb: granted' /var/log/slate-security.log)" 1
check sudo_env_refused "$(su tester -c 'sudo -n -E echo x' 2>&1)" "sudo: sorry, you are not allowed to preserve the environment"
check sudo_setenv "$(su tester -c 'SLATE_X=1 sudo -n -E -u nobody env' 2>&1 | grep -c '^SLATE_X=1$')" 1
check sudo_env_list "$(su tester -c 'SLATE_X=1 SLATE_Z=2 sudo -n --preserve-env=SLATE_Z -u nobody env' 2>&1 | grep -c '^SLATE_[XZ]=')" 1
check sudo_list_alias "$(su tester -c 'sudo -l' | grep -c 'NOPASSWD: /bin/echo, /bin/printf, /bin/true ""')" 1
check sudo_env_all "$(su ann -c 'SLATE_Y=2 sudo -n -E sh -c "echo \$SLATE_Y"' 2>&1)" 2
echo 'defaults env_keep += "SLATE_K*", secure_path=/bin:/sbin' >> /etc/slate/broker.conf
check sudo_defaults_env "$(su ann -c 'SLATE_KV=3 SLATE_Y=4 sudo -n sh -c "echo \$SLATE_KV \$SLATE_Y \$PATH"' 2>&1)" "3 /bin:/sbin"
check sudo_preserve_groups "$(su ann -c 'sudo -n -P -u tester id -Gn' 2>&1 | tr ' ' '\n' | grep -c '^wheel$') $(su ann -c 'sudo -n -u tester id -Gn' 2>&1 | tr ' ' '\n' | grep -c '^wheel$')" "1 0"
check sudo_chdir_refused "$(su ann -c 'sudo -n -D /tmp pwd' 2>&1)" "sudo: sorry, you are not allowed to set the directory (-D)"
check sudo_timeout_refused "$(su ann -c 'sudo -n -T 1 true' 2>&1)" "sudo: sorry, you are not allowed to set a command timeout"
echo 'defaults runcwd=*, user_command_timeouts' >> /etc/slate/broker.conf
check sudo_chdir "$(su ann -c 'cd / && sudo -n -D /tmp pwd' 2>&1)" /tmp
# The shell says the command was ended by SIGTERM.
check sudo_timeout "$(su ann -c 'sudo -n -T 1 sleep 20; echo $?' 2>&1)" "sudo: command timed out
Terminated
143"
check sudo_selinux "$(sudo -r sysadm_r id 2>&1)" "sudo: SELinux roles and types (-r, -t) are not supported: Slate has no SELinux"
check sudo_help "$(sudo -h | head -1 | cut -c1-11)" "usage: sudo"
check sudo_host "$(sudo -h elsewhere -l 2>&1; sudo -h localhost -l | head -1)" "sudo: elsewhere: only this machine's commands can be run or listed
User root may run the following commands:"
printf '#!/bin/sh\necho annpw\n' > /tmp/sudo-askpass.sh
chmod 755 /tmp/sudo-askpass.sh
check sudo_askpass_unset "$(su ann -c 'sudo -k; sudo -A id -u' 2>&1)" "sudo: no askpass program specified, try setting SUDO_ASKPASS"
check sudo_askpass "$(su ann -c 'SUDO_ASKPASS=/tmp/sudo-askpass.sh sudo -A id -u' 2>&1)" 0
echo 'defaults log_input, log_output' >> /etc/slate/broker.conf
check sudo_iolog_run "$(su ann -c "echo in | sudo -n sh -c 'cat; echo out; echo err >&2'" 2>&1 | sort | tr '\n' ' ')" "err in out "
check sudo_iolog_dir "$(stat -c '%a %U' /var/log/sudo-io)" "700 root"
check sudo_iolog_target "$(su ann -c "sudo -n -u tester sh -c 'echo as-tester'" 2>&1)" as-tester
check sudo_iolog_logged "$(grep -c '(I/O log [0-9A-Z]*): granted' /var/log/slate-security.log)" 2
id=$(sudoreplay -l user ann command 'echo out' | tail -1 | sed 's/.*TSID=\([0-9A-Z]*\) .*/\1/')
check sudoreplay_list "$(sudoreplay -l user ann | grep -c ' : ann : TTY=')" 2
check sudoreplay "$(sudoreplay -m 0 $id | sort | tr '\n' ' ')" "err in out "
check sudoreplay_stdin "$(sudoreplay -m 0 -f stdin $id)" in
check sudoreplay_target "$(sudoreplay -l runas tester | grep -c 'COMMAND=sh -c echo as-tester')" 1
check sudoreplay_target_play "$(sudoreplay -m 0 $(sudoreplay -l runas tester | tail -1 | sed 's/.*TSID=\([0-9A-Z]*\) .*/\1/'))" as-tester
echo 'defaults timestamp_timeout=0' >> /etc/slate/broker.conf
check sudo_timestamp_timeout "$(su ann -c 'sudo -n id -u' 2>&1)" "sudo: a password is required"
rm -f /tmp/sudo-askpass.sh
rm -f /etc/sudo-link /etc/sudo-test.conf /tmp/sudo-ed.sh /tmp/sudo_bg
cp /tmp/broker.conf.saved /etc/slate/broker.conf
userdel -r ann
kill $broker 2>/dev/null
exit $fail
