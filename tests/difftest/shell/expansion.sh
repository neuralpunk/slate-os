# Parameter expansion, arithmetic, braces, tilde and globs.
s=hello.tar.gz
echo ${s%.*} ${s%%.*} ${s#*.} ${s##*.}
echo ${#s} ${s:2} ${s:1:3} ${s: -2} ${s:(-5):2}
echo ${s/l/L} ${s//l/L} ${s/#h/H} ${s/%gz/xz} ${s/l*/X}
echo ${s^} ${s^^} X${s,,}
u=
echo ${u:-dash} ${u-nodash} ${u:+plus} ${s:+plus}
echo ${new:=assigned} $new
(echo ${unset_var:?is unset}) 2>/dev/null; echo "status $?"
echo $((1 + 2 * 3)) $(( (1+2)*3 )) $((7 / 2)) $((7 % 3)) $((-7 / 2))
echo $((1 << 4)) $((0xff)) $((010)) $((2#101)) $((3 > 2 && 1)) $((5 ? 6 : 7))
i=5; echo $((i++)) $i $((++i)) $((i += 10)) $i
echo $(( i == 17 )) $((~0)) $((!0))
a=3 b=4; echo $((a * b)) $((a ** 2))
echo {a,b,c}x pre{1..4} {5..1} {a..e} {01..03} {1..10..3}
echo x{,y}z {a,b}{1,2}
echo ~ ~/sub "~"
mkdir -p g && cd g && touch b.c a.c c.h .hid
echo *.c
echo *
echo .*
echo [ab].c
echo ?.h
echo nomatch*
echo "*.c" '*'
echo [!a].c
set -f; echo *.c; set +f
cd ..
echo $((  2  +  3  ))
x=10; y=x; echo $(( y + 1 ))
