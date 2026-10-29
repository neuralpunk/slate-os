# Pipelines, subshells and background jobs.
echo abc | tr a-z A-Z | rev
printf '3\n1\n2\n' | sort | head -n 2
x=outer; echo inner | read x; echo "x=$x"
false | true; echo "pipe $?"
true | false; echo "pipe $?"
set -o pipefail; false | true; echo "pipefail $?"; set +o pipefail
sleep 0.1 & pid=$!; wait $pid; echo "waited $?"
(exit 4) & wait $!; echo "bg status $?"
{ for i in 1 2 3; do echo $i & done; wait; } | sort; echo all done
echo $(echo a; echo b)
echo "$(echo a; echo b)"
n=$(printf '%s\n' a b c | wc -l); echo $n
(cd /tmp; pwd); pwd | grep -c tmp
echo $$ | grep -c '^[0-9]*$'
[ "$(echo $$)" = "$$" ] && echo same pid in cmdsub
yes | head -n 2
