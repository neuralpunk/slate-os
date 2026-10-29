# Arrays, associative arrays, declare/typeset/local, mapfile, process
# substitution and the other bash extensions chalk has (M21 phase 3).
a=(one two "three four")
echo "${#a[@]} ${a[0]} ${a[2]} ${a[-1]}"
for x in "${a[@]}"; do echo "[$x]"; done
echo "${a[*]}"
a+=(five)
a[10]=ten
echo "${#a[@]} ${!a[@]}"
echo "${a[@]:1:2}"
unset 'a[1]'
echo "${!a[@]} ${a[@]}"
b=("${a[@]}")
echo "${#b[@]} ${!b[@]}"
echo "${#a[2]}"
i=2; echo "${a[i]} ${a[$i]} ${a[i+8]}"
s=scalar; s[1]=more; echo "${s[@]} ${#s[@]}"
echo "${a}"
declare -a e; echo "${#e[@]} [${e[@]}]"
declare -p a b e
declare -A m
m[apple]=red; m[banana]=yellow; m["cherry pie"]=sweet
echo "${m[apple]} ${m[cherry pie]} ${#m[@]}"
printf '%s\n' "${!m[@]}" | sort | while read -r k; do echo "$k"; done
unset 'm[apple]'; echo "${#m[@]} ${m[apple]-gone}"
declare -A n=([x]=1 [y]=2); n[x]+=0; echo "${n[x]} ${n[y]}"
declare -A one=([k]=v); declare -p one
declare -i num=5; num+=3; num=num*2; echo $num
declare -i num2; num2='2 + 3'; echo $num2
declare -l low=MiXeD; declare -u up=MiXeD; echo "$low $up"
low=ABC; echo $low
declare -r ro=fixed; (ro=changed) 2>/dev/null; echo "$? $ro"
declare -p ro num low
declare -x exp=1; sh -c 'echo child $exp'
typeset t=typed; echo $t
f() { local -a la=(1 2 3); local lv; echo "${#la[@]} [${lv-unset}]"; declare inner=in; declare -g outer=out; }
f; echo "[${la[@]}] [${inner-none}] [$outer]"
g() { local v=local; h; }; h() { echo "dynamic $v"; }; v=global; g; echo "$v"
printf 'l1\nl2\nl3\n' > /tmp/chalk_arr_$$
mapfile -t lines < /tmp/chalk_arr_$$; echo "${#lines[@]} ${lines[1]}"
mapfile lines2 < /tmp/chalk_arr_$$; printf '[%s]' "${lines2[@]}"; echo
readarray -t -s 1 -n 1 part < /tmp/chalk_arr_$$; echo "${part[@]}"
mapfile -t < /tmp/chalk_arr_$$; echo "${MAPFILE[2]}"
mapfile -t -O 5 lines < /tmp/chalk_arr_$$; echo "${!lines[@]}"
printf 'a,b,c' | { mapfile -d , -t parts; echo "${parts[1]} ${#parts[@]}"; }
rm -f /tmp/chalk_arr_$$
echo "x y  z" | { read -a words; echo "${#words[@]} ${words[2]}"; }
cat <(echo from procsub)
while read l; do echo "got $l"; done < <(printf 'p\nq\n')
diff <(printf '1\n2\n') <(printf '1\n2\n') && echo same
printf -v out '%s-%s' a b; echo $out
x=hello; ref=x; echo "${!ref}"
arr=(p q r); ref='arr[1]'; echo "${!ref}"
echo "${a[@]/o/0}"
echo "${a[@]^^}"
echo "${!m*}" | tr ' ' '\n' | grep -c '^m$'
declare -p nosuch 2>/dev/null; echo "status $?"
unset a; echo "${#a[@]}"
c=(); echo "${#c[@]}"
d=([3]=x [1]=y z); echo "${!d[@]} ${d[@]}"
arr2=(1 2 3); echo $(( arr2[1] + arr2[2] ))
(( arr2[0] = 9 )); echo "${arr2[0]}"
[[ "key=value" =~ ^([a-z]+)=([a-z]+)$ ]] && echo "${#BASH_REMATCH[@]} ${BASH_REMATCH[0]} ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
[[ "ab" =~ (x)?b ]]; echo "${#BASH_REMATCH[@]} [${BASH_REMATCH[1]}]"
[[ "zzz" =~ ^a ]]; echo "${#BASH_REMATCH[@]} $?"
