# Built-in commands.
echo "a b c d" | { read x y z; echo "$x|$y|$z"; }
echo "  lead trail  " | { read v; echo "[$v]"; }
echo 'back\slash' | { read v; echo "$v"; }
echo 'back\slash' | { read -r v; echo "$v"; }
printf 'x:y:z\n' | { IFS=: read a b c; echo "$a $b $c"; }
printf 'no newline' | { read v; echo "$? $v"; }
set -- -a -b val -c rest
while getopts ab:c o; do echo "opt $o ${OPTARG-none}"; done
shift $((OPTIND - 1)); echo "left $*"
OPTIND=1
set -- -x
getopts :ab o; echo "silent $o $OPTARG"
set -- 1 2 3 4; shift 2; echo "$@"; shift 5; echo "shift $?"
eval 'echo eval $((1+1))'; cmd='x=5'; eval "$cmd"; echo $x
printf -v pv '%03d' 7; echo $pv
export EXPORTED=yes; sh -c 'echo child $EXPORTED'
NOTEXP=no; sh -c 'echo child "[$NOTEXP]"'
TEMP=tmp sh -c 'echo temp $TEMP'; echo "after [$TEMP]"
unset x; echo "unset [${x-gone}]"
readonly RO=1; (RO=2) 2>/dev/null; echo "ro $?"
command -v echo cd; command -v nonexistent; echo "cv $?"
type cd | head -c 5; echo
alias greet='echo hello'
greet world
unalias greet
(trap 'echo exit trap' EXIT; echo body)
trap - EXIT
(set -e; false; echo not reached); echo "errexit $?"
(set -e; false || true; if false; then :; fi; echo survived)
(set -u; echo $undefined_thing) 2>/dev/null; echo "nounset $?"
let 'z = 3 * 4'; echo $z
true; echo $?; false; echo $?
: ignored args; echo colon $?
test 1 -eq 1 && [ a = a ] && echo tests
f() { echo "\$0 kept, \$1=$1"; }; f one
umask 022; umask
cd /; pwd; cd - > /dev/null; [ "$PWD" != / ] && echo back
x=1; x+=2; echo $x
set -- "a b" c; echo "$#: $1"
v=$(exit 3); echo "cmdsub status $?"
