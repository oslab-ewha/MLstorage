#!/bin/bash

function usage() {
	    cat <<EOF
Usage: mlstorctl -c -b <backing device> -s <nn size> <mlstor name>
       mlstorctl -d <mlstor name>
EOF
}

MGMT=/sys/kernel/stolearn-nn/mgmt

function get_sectors() {
    size=`lsblk -bln -o SIZE $1 | head -n 1`
    expr $size / 512
}

function get_cur_nns() {
    (cat $MGMT | grep -Eo '^stolearn-nn[[:digit:]]+' | grep -Eo [[:digit:]]+ | sort) 2> /dev/null
}

function guess_new_nn() {
    for nn in `get_cur_nns`; do
	echo $1 | grep -wq $nn
	if [ $? -ne 0 ]; then
	    echo $nn
	    exit
	fi
    done
}

function get_attached_nn() {
    (dmsetup table $1 | grep -Eo 'stolearn-nn[[:digit:]]+' | grep -Eo [[:digit:]]+) 2> /dev/null
}

function create_mlstor() {
    if [[ ! -d /sys/kernel/stolearn-nn ]]; then
	echo "stolearn-nn kernel module not installed"
	exit 3
    fi
    nns=`get_cur_nns`
    echo "stolearn-nn attach $2" > /sys/kernel/stolearn-nn/mgmt
    nn=`guess_new_nn "$nns"`
    size=`expr $2 \* 80`
    total_mem=`grep MemTotal /proc/meminfo | awk '{print $2}'`
    size_max=`expr $total_mem / 1024 / 2`
    if [[ $size -gt $size_max ]]; then
       size=$size_max
    fi
    sectors=`get_sectors $1`
    echo "0 $sectors stolearn-cache $1 /dev/stolearn-nn$nn $size" | dmsetup create $3 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "failed to create MLstorage: $1"
	echo "stolearn-nn detach $nn" > /sys/kernel/stolearn-nn/mgmt 2> /dev/null
	exit 2
    fi
}

function delete_mlstor() {
    dmsetup info $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "MLstorage not found: $1"
	exit 3
    fi
    nn=`get_attached_nn $1`
    dmsetup remove $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "error: $1: failed to remove MLstorage: is it mounted?"
	exit 4
    fi
    echo "stolearn-nn detach $nn" > /sys/kernel/stolearn-nn/mgmt 2> /dev/null
}

if [[ $EUID -ne 0 ]]; then
    echo "mlstorctl should be run as root" 
    exit 2
fi

create=
delete=
backdev=
size=
while getopts "cdb:s:h" arg
do
    case $arg in
	c)
	    create=true
	    ;;
	d)
	    delete=true
	    ;;
	s)
	    size=$OPTARG
	    ;;
	b)
	    backdev=$OPTARG
	    ;;
	h)
	    usage
	    exit 0
	    ;;
	*)
	    usage
	    exit 1
	    ;;
    esac
done

shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

name=$1

if [[ -n $create ]]; then
    if [[ -z $backdev ]]; then
	echo "backing device is required"
	exit 3
    fi
    if [[ -z $size ]]; then
	echo "size is required"
	exit 3
    fi
    create_mlstor $backdev $size $name
elif [[ -n $delete ]]; then
    delete_mlstor $name
else
    echo "You should run with -c or -d"
    exit 1
fi
