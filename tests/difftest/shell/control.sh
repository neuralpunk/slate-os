# Compound commands, functions and control flow.
if false; then echo no; elif true; then echo elif; else echo else; fi
i=0
while [ $i -lt 5 ]; do i=$((i+1)); [ $i = 2 ] && continue; [ $i = 4 ] && break; echo w$i; done
until [ $i -le 0 ]; do i=$((i-1)); done; echo until $i
for x in a b c; do for y in 1 2 3; do [ $y = 2 ] && continue 2; [ $x = c ] && break 2; echo $x$y; done; done
for x; do echo never; done
case abc in a*) echo star;; *) echo no;; esac
case x in y|x) echo alt;; esac
case "a b" in "a b") echo quoted;; esac
case f in [a-f]) echo class;; esac
case z in a) ;; *) echo default;; esac
case a in a) echo one;& b) echo fall;; c) echo no;; esac
case a in a) echo m1;;& a) echo m2;; esac
f() { echo "f has $# args: $*"; return 3; }
f 1 2 3; echo "ret $?"
g() { local v=inner; echo $v; }
v=outer; g; echo $v
fact() { if [ $1 -le 1 ]; then echo 1; else echo $(( $1 * $(fact $(( $1 - 1 ))) )); fi; }
fact 6
count() { n=0; while :; do n=$((n+1)); [ $n -ge 3 ] && return $n; done; }
count; echo count $?
{ echo group; echo two; } | wc -l
( exit 7 ); echo sub $?
x=1; ( x=2 ); echo x=$x
true && echo and1 || echo or1
false && echo and2 || echo or2
! false; echo bang $?
! true; echo bang $?
[[ abc == a* ]] && echo dbl1
[[ abc != a* ]] || echo dbl2
[[ -z "" && -n x ]] && echo dbl3
[[ 2 -lt 10 ]] && echo dbl4
[[ b > a ]] && echo dbl5
(( 3 > 2 )) && echo arith1
(( 0 )) || echo arith2
function kw { echo keyword function; }
kw
h() { echo "in h: $1"; }; h "$(echo arg)"
loopf() { for i in 1 2 3; do [ $i = 2 ] && return 9; done; }; loopf; echo loopf $?
[[ abc123 =~ [0-9]+$ ]] && echo "re1 $BASH_REMATCH"
[[ a.c =~ "a.c" ]] && echo re2
[[ abc =~ "a.c" ]] || echo re3
[[ x =~ ^(y|x)$ ]] && echo re4
