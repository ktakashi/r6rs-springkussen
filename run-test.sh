#!/bin/bash

declare -a implementations=($(scheme-env list -l))

echo "Preparing for Chez Scheme"
create_symlink() {
    flag=$1
    target=$2
    src=$3
    if [ ! ${flag} ${src} ]; then
	ln -s ${target} ${src}
    fi
}
create_symlink -f %3a64.chezscheme.sls test/lib/srfi/:64.sls
create_symlink -d %3a64 test/lib/srfi/:64

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

EXIT_STATUS=0

for impl in ${implementations[@]}; do
    echo Testing with ${impl}
    name=${impl%@*}
    for file in $(find test -name '*.scm'); do
	echo $file
	scheme-env run ${impl} \
		   --loadpath src \
		   --loadpath test/lib \
		   --standard r6rs --program ${file} | check_output
	
	# Do nothing
	case ${EXIT_STATUS} in
	    0) EXIT_STATUS=$? ;;
	esac
    done
    echo Done!
    echo
done

echo Library test status ${EXIT_STATUS}
exit ${EXIT_STATUS}
