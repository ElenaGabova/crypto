#!/bin/sh

echo "Tests of ARMv7 Whirlpool implementations"
echo "We use qemu-arm to emulate ARMv7 and OpenSSL to generate"
echo "random bytes"
echo ""

OIFS="$IFS"
IFS='
'
RESULT="Tests are passed"

function check()
{
	if [ "${r[0]}" == "${r[2]}" ]; then
		echo "REF implementation has got the same result as REFO implementation"
	else
		echo "REF implementation has got other result than REFO implementation"
		RESULT="Tests are not passed"
	fi
	if [ "${r[0]}" == "${r[3]}" ]; then
		echo "SLOW implementation has got the same result as REFO implementation"
	else
		echo "SLOW implementation has got other result than REFO implementation"
		RESULT="Tests are not passed"
	fi
	if [ "${r[0]}" == "${r[4]}" ]; then
		echo "ASMV implementation has got the same result as REFO implementation"
	else
		echo "ASMV implementation has got other result than REFO implementation"
		RESULT="Tests are not passed"
	fi
	if [ "${r[0]}" == "${r[5]}" ]; then
		echo "ASMU implementation has got the same result as REFO implementation"
	else
		echo "ASMU implementation has got other result than REFO implementation"
		RESULT="Tests are not passed"
	fi
}

echo "String tests"

STRS=(
	"The quick brown fox jumps over the lazy dog"
	"The quick brown fox jumps over the lazy eog"
	""
	"test"
)

for s in "${STRS[@]}"; do
	echo "Testing with string \""$s"\""
	r=(`qemu-arm ./test_whirlpool -q -s "$s"`)
	check
	echo ""
done

echo "File tests"

FILES=(
	"./test_whirlpool"
	"./tests_whirlpool.sh"
)

for f in "${FILES[@]}"; do
	echo "Testing with file \""$f"\""
	r=(`qemu-arm ./test_whirlpool -q -f "$f"`)
	check
	echo ""
done

echo "Tests with random strings"
COUNT=10

for i in $(seq 1 $COUNT); do
	LEN=$RANDOM
	let "LEN %= 100"
	s=`openssl rand -hex $LEN`
	let "LEN *= 2"
	echo "Using random string of length $LEN"

	r=(`qemu-arm ./test_whirlpool -q -s "$s"`)
	check
	echo ""
done

IFS="$OIFS"
echo ""
echo "$RESULT"
