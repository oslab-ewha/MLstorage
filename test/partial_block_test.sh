#!/bin/bash

. ./test-helpers.sh

testSmallBlock() {
    create_disk 1024
    disk_caching=$disk
    create_disk 10240
    disk_backing=$disk

    dd if=/dev/random of=.random.$$.blk bs=512 count=8 >& /dev/null
    dd if=.random.$$.blk of=$disk_backing >& /dev/null

    create_mlstor $disk_caching $disk_backing mlstor

    dd if=.random.$$.blk of=mlstor.dev bs=512 count=1 seek=1 oflag=direct

    dd if=$disk_backing of=.random.$$.copied bs=512 count=1 skip=1 iflag=direct

    dd if=.random.$$.blk of=.random.$$.checked bs=512 count=1 iflag=direct
    
    diff .random.$$.checked .random.$$.copied
    ans=$?

    rm -f .random.$$.*

    delete_mlstor mlstor

    assertTrue $ans
}

go_test

