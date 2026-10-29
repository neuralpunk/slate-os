# Corner cases.
y='p q'
echo ${x:-"a b"} ${x:-$y} "${x:-$y}"
set -- 1 2 3
echo "x$@y"
echo ${#@} ${#*}
IFS=; echo $*; echo "$*"; unset IFS
echo "${y#"p"}" ${y#\p} "${y%"*"}"
star='*'; echo "${star}" ${star#"*"}x
e='1+2'; echo $((e)) $((e * 2)) $((unset_v + 1))
case '*' in '*') echo literal star;; esac
case x in "$star") echo bad;; *) echo good;; esac
q() { cat <<EOT
fn heredoc $1
EOT
}
q arg
printf '%s-%s\n' a b c d e
printf '%d\n' 0x10 '"A'
echo 'x' | while read l; do echo "loop $l"; done; echo "after loop"
cat > lib.sh <<'EOT'
libvar=set
libf() { echo "libf $1"; }
return 5
echo unreachable
EOT
. ./lib.sh; echo "dot status $?"; libf x; echo $libvar
f() { echo first; }; f() { echo second; }; f
z=$( (echo sub; exit 3) ); echo "$z $?"
echo $(( 2 > 1 ? 10 : 20 ))
v="a  b"; set -- $v; echo $#; set -- "$v"; echo $#
echo "$(echo "$(echo "$(echo nest3)")")"
w=$'line1\nline2'; echo "$w" | wc -l
for i in $(seq 3); do printf '%s ' $i; done; echo
n=0; while [ $n -lt 1000 ]; do n=$((n+1)); done; echo $n
words="one two three"; for w in $words; do printf '[%s]' "$w"; done; echo
arr="a,b,c"; IFS=, read p1 p2 p3 <<EOT
$arr
EOT
echo "$p1 $p2 $p3"
echo "${HOME:+home set}"
: ${defaulted:=dv}; echo $defaulted
t=abc; echo ${t:5} "${t:1:10}" ${t: -1}
echo \
continued
echo "a
b"
echo -n; echo -- -n
[ -d / ] && [ ! -f / ] && echo testops
echo $( echo ')' )
echo "$( case x in x) echo inside-case;; esac )"
