#!/bin/bash

declare -a implementations=($(scheme-env list -l))

./test/bin/pre-test.sh

check_output() {
    local status=0
    while IFS= read -r LINE; do
	echo $LINE
	case $LINE in
	    *FAIL*) status=255 ;;
	    *Exception*) status=255 ;;
	esac
    done
    return ${status}
}

DATA_DIR=$(readlink -f test/data)

EXIT_STATUS=0

for impl in ${implementations[@]}; do
    echo Testing with ${impl}
    name=${impl%@*}
    for file in $(find test -name '*.scm'); do
	echo $file
	scheme-env run ${impl} \
		   --loadpath src \
		   --loadpath test/lib \
		   --standard r6rs \
		   --program ${file} --  $DATA_DIR | check_output
	TMP=$?
	# Do nothing
	case ${EXIT_STATUS} in
	    0) EXIT_STATUS=$TMP ;;
	esac
    done
    echo Done!
    echo
done

./test/bin/post-test.sh

echo Library test status ${EXIT_STATUS}
exit ${EXIT_STATUS}
