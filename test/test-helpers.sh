#!/bin/bash

n_files=0
lofiles[0]=
lodevs[0]=

oneTimeSetUp() {
    insmod ./mlstor.ko
    mknod mlstor.dev b 253 1
    mkdir mnt
}

oneTimeTearDown() {
    if [ $n_files -gt 0 ]; then
	for i in `seq $n_files`; do
	    idx=`expr $i - 1`
	    losetup -d ${lodevs[$idx]} >& /dev/null
	    rm -f ${lofiles[$idx]}
	done
    fi

    rmmod ./mlstor.ko >& /dev/null
    rm -f mlstor.dev
    rmdir mnt >& /dev/null
}

setUp() {
    cleanup=
}

tearDown() {
    if [[ -n $cleanup ]]; then
	return
    fi
    $cleanup
}

create_disk() {
    disk=
    lofile=testfile.$RANDOM
    lofiles[$n_files]=$lofile
    dd if=/dev/zero of=${lofiles[$n_files]} bs=4096 count=$1 >& /dev/null
    if [ $? -ne 0 ]; then
	fail "can't dd"
	return 1
    fi
    disk=`losetup -f`
    lodevs[$n_files]=$disk
    losetup -f ${lofiles[$n_files]}
    if [ $? -ne 0 ]; then
	rm -f $lofile
	fail "failed to losetup"
    fi
    n_files=`expr $n_files + 1`
}

create_mlstor() {
    ./mlstorctl.sh -c -C $1 -b $2 $3
    if [ $? -ne 0 ]; then
	fail "failed to create mlstor"
    fi
}

delete_mlstor() {
    ./mlstorctl.sh -d $1
}

go_test() {
    if [[ `id -u` != 0 ]]; then
	echo "should be run as root"
	exit 1
    fi

    if [[ -z $SHUNIT2 ]]; then
	echo "SHUNIT2 is not defined"
	exit 2
    fi

    . $SHUNIT2
}
