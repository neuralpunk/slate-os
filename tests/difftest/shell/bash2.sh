# bash extensions chalk gained with g218: arithmetic for, select,
# coprocesses, namerefs, shopt, mapfile callbacks, LINENO, FUNCNAME,
# PIPESTATUS, printf %q, associative arrays in bash's order, empty
# fields kept by "".
set --; n() { echo "n=$#"; }; n "$@"; n "${a[@]}"; a=(); n "${a[@]}"; n "$@" ""; n "x$@"; n "$*"; n ""$@
x=" a"; set -- ""$x; echo "1: $#"
x="a "; set -- $x""; echo "2: $#"
x="a "; y=" b"; set -- $x""$y; echo "3: $# [$2]"
alias hi='echo HI'
echo "4: $(hi) `hi`"
for ((i=0, j=10; i<3; i++, j--)); do echo "$i $j"; done
for ((;;)) { echo once; break; }
echo $[2*3]
declare -n r=x; r=5; echo "$x ${!r} $r"; declare -p r; unset r; echo "x=${x-unset}"
declare -n s=arr; s[1]=b; s+=(c); echo "${arr[@]} ${#s[@]}"; unset -n s; echo "${s-gone} ${arr[1]}"
g() { local -n out=$1; out=(1 2 3); }; g res; echo "${res[@]}"
declare -n e="a2[1]"; a2=(p q); echo "$e"; e=Z; echo "${a2[@]}"
printf '2\n\n3\n' | { select v in a b c; do echo "v=$v R=$REPLY"; [ "$v" = c ] && break; done; } 2>&1
printf '1\n' | { COLUMNS=30; select v in one two three four five six seven eight nine ten eleven; do break; done; } 2>&1
coproc { read l; echo "got $l"; }
echo hi >&"${COPROC[1]}"; read rr <&"${COPROC[0]}"; echo "$rr"; wait $COPROC_PID; echo "after: [${COPROC[*]}]"
shopt -s extglob
case foo.c in @(*.c|*.h)) echo ext-yes;; esac; x=abcabc; echo "${x//+(abc)/X} ${x##*(abc)}"
case foo in !(bar)) echo not-bar;; esac
shopt -u extglob
[[ fooX == foo@(X|Y) ]] && echo cond-ext
shopt -s nocasematch; case ABC in abc) echo nocase;; esac; [[ ABC == a* ]] && echo nocase2; shopt -u nocasematch
mkdir -p gt/a/b gt/c; touch gt/a/x gt/a/b/y gt/z gt/.h; cd gt
shopt -s globstar; echo **; echo **/; echo a/**; echo **/y; shopt -u globstar
echo */x; echo */nope
shopt -s dotglob; echo *; shopt -u dotglob
shopt -s nullglob; echo n: *.nomatch; shopt -u nullglob
shopt -s nocaseglob; echo Z*; shopt -u nocaseglob
cd ..
shopt -s lastpipe; echo piped | read lp; echo "lp=$lp"; shopt -u lastpipe
shopt extglob globstar; echo "st=$?"; shopt -q expand_aliases && echo q-on; shopt -p nullglob; shopt -s | head -3
cb() { echo "cb $1 [$2]"; }; printf 'l1\nl2\nl3\nl4\n' | { mapfile -t -C cb -c 2 m; echo "${m[@]}"; }
h() { echo "${FUNCNAME[@]} $LINENO"; }; k() { h; }; k
echo "line $LINENO"
true | false | true; echo "${PIPESTATUS[@]}"; false; echo "${PIPESTATUS[@]}"
printf '[%q] ' "a b" "" "it's" $'a\tb' '~x' 'a,b=c'; echo
printf '%-6q|%5q|\n' ab ab
declare -A m=([one]=1 [two]=2 [three]=3 [four]=4 [five]=5 [alpha]=a [beta]=b)
echo "${!m[@]}"; m[gamma]=g; unset 'm[two]'; echo "${!m[@]}"; declare -p m
t=$( { time -p true; } 2>&1 ); echo "${t%% *}"
TIMEFORMAT='%%|%0R'; t=$( { time true; } 2>&1 ); echo "$t"
(trap 'echo usr1' USR1; echo "$(trap -p USR1 | wc -l)")
shift 5; echo "shift=$?"
d=$PWD; pushd /usr >/dev/null; pushd /etc; dirs -v; popd; pushd; pushd +1; popd -0; dirs -c; dirs; cd "$d"
builtin echo via-builtin; builtin nosuch 2>/dev/null; echo "st=$?"
cf() { caller 0; cg; }; cg() { caller 0; caller 1; caller 2; echo "caller=$?"; }; cf
