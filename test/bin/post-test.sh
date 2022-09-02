#!/bin/bash

delete_link() {
    target=$1
    if [ -s "${target}" ]; then
	rm "${target}"
    fi
}

delete_link test/lib/srfi/:64.sls
delete_link test/lib/srfi/:64
