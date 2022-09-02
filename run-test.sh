#!/bin/bash

declare -a implementations=($(scheme-env list -l))

set -o pipefail

./test/bin/pre-test.sh

check_output() {
    local status=0
    while IFS= read -r LINE; do
	echo ${LINE}
	case "${LINE}" in
	    *FAIL*) status=255 ;;
	    *Exception*) status=255 ;;
	    *"Unhandled exception"*) status=255 ;;
	esac
    done
    return ${status}
}

DATA_DIR=$(readlink -f test/data)

EXIT_STATUS=0

run_dir() {
    DIR=$1
    MSG=$2
    for impl in ${implementations[@]}; do
	echo ${MSG} ${impl}
	name=${impl%@*}
	for file in $(find ${DIR} -name '*.scm'); do
	    echo $file
	    scheme-env run ${impl} \
		       --loadpath src \
		       --loadpath test/lib \
		       --standard r6rs \
		       --program ${file} --  ${DATA_DIR} | check_output
	    TMP=$?
	    case ${EXIT_STATUS} in
		0) EXIT_STATUS=${TMP} ;;
	    esac
	done
	echo Done!
	echo
    done
}

./test/bin/post-test.sh

run_dir test "Testing with"

echo Library test status ${EXIT_STATUS}

run_dir doc/examples "Running examples"

echo Examples execution status ${EXIT_STATUS}

exit ${EXIT_STATUS}
