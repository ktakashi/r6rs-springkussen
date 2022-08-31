#!/bin/bash

echo "Preparing for Chez Scheme"
echo

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
