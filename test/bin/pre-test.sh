#!/bin/bash

set -e

echo "Preparing for Chez Scheme"

create_symlink() {
    flag=$1
    src=$2
    target=$3
    if [ ! "${flag}" "${target}" ]; then
	echo "Creating symlink: ${src} -> ${target}"
	ln -s ${src} ${target}
    fi
}

CUR=$(pwd)
cd test/lib/srfi
create_symlink -f '%3a64.chezscheme.sls' ':64.sls'
create_symlink -d '%3a64' ':64'

cd $CUR

echo Done
echo
