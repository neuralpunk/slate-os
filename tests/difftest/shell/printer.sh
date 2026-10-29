# The command printer (g218): declare -f and type show functions as
# bash lays them out.
f1() { a=1 b="x y" echo 'q' "d$x" $(echo l) `pwd` $((1+2)) ${v:-d} a\ b >/dev/null 2>&1 </dev/null; }
f2() { if a; then b; elif c; then d; else e; fi; }
f3() { while a && b || ! c; do x | y |& z; done; until q; do :; done; }
f4() { case $x in a|b) one;; *) two ;& c) three;;& esac; }
f5() { (cd /; ls) > o; { a; b; } 2>/dev/null; a & b; c & }
f6() { [[ -n $x && ( $y == a* || $z =~ ^b(c)$ ) ]]; (( i++ , j=2 )); [[ x ]]; }
f7() { for i in 1 2 3; do echo $i; done; for j; do :; done; for ((i=0;i<3;i++)); do echo; done; }
f8() { cat <<EOT
hello $x
EOT
cat <<'Q' >f
lit
Q
echo after; }
f9() { local -a arr=(1 "2 3" [5]=x); echo "${arr[@]}" ${#arr[*]} ${!arr[@]} ${x#a} ${x%%b*} ${x/a/b} ${x:1:2} ${x^^}; }
f10() { echo $'a\nb' "it's" 'say "hi"' a\"b "a\"b" "\$h"; }
f11() { g() { echo inner; }; g; }
function f12 { echo kw; }
f13() ( echo sub )
f14() { a >>f; b &>g; c &>>h; d <<<"$x"; e 3<>rw; f 4<&0; g 5>&-; h >|clob; j 1>f; k 0<f; }
f15() { select x in a b; do break; done; time sleep 0; ! true; true || { echo x; }; }
f16() { case y in (z) q;; w) ;; esac; x=1 y=2; coproc N { cat; }; }
declare -f
declare -F
declare -f f2 f13
type f12
type -t f12 echo if ls
