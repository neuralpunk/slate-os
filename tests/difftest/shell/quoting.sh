# Quoting, field splitting and positional parameters.
echo 'single $HOME' "double" \$escaped "a\"b" 'it'\''s'
echo "tab	in quotes" a\ b
echo $'ansi\tc\x41\n' end
x='  lots   of   space  '
echo [$x]
echo ["$x"]
set -- $x
echo $#
set -- "a b" c "" d
echo $#
for a in "$@"; do echo "<$a>"; done
for a in $@; do echo "[$a]"; done
for a in "$*"; do echo "{$a}"; done
IFS=:
echo "$*"
v=a:b::c
set -- $v
echo $# "$1" "$2" "$3" "$4"
IFS=' :'
v=' a : b  '
set -- $v
echo $# "$1" "$2"
unset IFS
v='x  y'
set -- $v
echo $#
e=
set -- $e "$e" ''$e
echo $#
printf '%s|' "${@}"; echo
echo "nested $(echo "inner $(echo deep)")"
echo `echo back\`tick\``
echo "$(printf 'a\n\n\n')" end
echo ${undefined-default} "${undefined:-x y}"
