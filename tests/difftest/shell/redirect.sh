# Redirections and here-documents.
echo one > f; echo two >> f; cat f
cat < f | wc -l
echo err 1>&2 2>/dev/null
{ echo out; echo err >&2; } 2>&1 | sort
{ echo out; echo err >&2; } 2>/dev/null
echo x >&-; echo "closed $?" 2>/dev/null
cat <<EOT
plain $HOME_unset_var ok
  indented $((1+1)) `echo bq`
EOT
cat <<'EOT'
quoted $HOME `x`
EOT
cat <<-EOT
	tabs stripped
		twice
	EOT
cat <<<"here string $((2*3))"
cat <<A; cat <<B
first
A
second
B
exec 3> fd3; echo via3 >&3; exec 3>&-; cat fd3
exec 4< f; read l <&4; echo "read $l"; exec 4<&-
while read line; do echo "got $line"; done < f
{ read a; read b; } < f; echo "$b $a"
echo data > g; cat 0<g
set -C; (echo no > g) 2>/dev/null; echo "clobber $?"; echo yes >| g; cat g; set +C
x=$(cat <<EOF2
in cmdsub
EOF2
)
echo "$x"
f2() { echo "fn out"; } ; f2 > h; cat h
for i in 1 2; do echo $i; done > loop; cat loop
echo both &> both; cat both
ls /nonexistent-dir 2>/dev/null || echo "ls failed"
