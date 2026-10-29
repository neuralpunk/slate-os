#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# chalk on Slate (M21 phase 3): what the bash comparison on the host
# cannot show: /dev/fd and /proc/self/fd links to pipes, process
# substitution, read -t, ulimit and times on Slate's kernel.
fail=0
check() {
    name=$1; shift
    if [ "$1" = "$2" ]; then
        echo "SLATE-TEST: PASS chalk::$name"
    else
        echo "SLATE-TEST: FAIL chalk::$name (got '$1', want '$2')"
        fail=$((fail + 1))
    fi
}
check dev_stdin_pipe "$(echo hi | cat /dev/stdin 2>&1)" hi
check dev_fd_pipe "$(echo hi | cat /dev/fd/0 2>&1)" hi
check proc_fd_pipe "$(echo hi | cat /proc/self/fd/0 2>&1)" hi
check procsub_in "$(cat <(echo from procsub))" "from procsub"
check procsub_loop "$(while read l; do printf '%s;' "$l"; done < <(printf 'a\nb\n'))" "a;b;"
check procsub_two "$(diff <(echo x) <(echo x) && echo same)" same
check procsub_out "$(echo out > >(cat > /tmp/chalk_ps); sleep 0.2; cat /tmp/chalk_ps)" out
rm -f /tmp/chalk_ps
check procsub_path "$(echo <(true) | grep -c '^/dev/fd/[0-9][0-9]*$')" 1
check read_timeout "$(sleep 2 | { read -t 0.3 v; echo $?; })" 142
check read_t0_empty "$(sleep 1 | { read -t 0; echo $?; })" 1
check read_t0_ready "$(echo x | { sleep 0.2; read -t 0; echo $?; })" 0
check read_t_line "$(echo line | { read -t 2 v; echo "$? $v"; })" "0 line"
check ulimit_n "$(ulimit -n 64; ulimit -n)" 64
check ulimit_child "$(ulimit -n 70; sh -c 'ulimit -n')" 70
check ulimit_hard "$(ulimit -Hn 80; ulimit -Hn; ulimit -Sn)" "80
80"
check ulimit_all "$(ulimit -a | grep -c '^open files')" 1
check ulimit_bad "$(ulimit -n abc 2>&1; echo $?)" "$0: line 34: ulimit: abc: invalid number
1"
check times_format "$(times | grep -cE '^[0-9]+m[0-9]+\.[0-9]{3}s [0-9]+m[0-9]+\.[0-9]{3}s$')" 2
check mapfile_proc "$(mapfile -t l < <(printf '1\n2\n3\n'); echo "${#l[@]} ${l[2]}")" "3 3"
check declare_p "$(a=(x 'y z'); declare -p a)" 'declare -a a=([0]="x" [1]="y z")'
check assoc "$(declare -A m=([k]=v); m[j]=w; echo "${m[k]}${m[j]} ${#m[@]}")" "vw 2"
exit $fail
