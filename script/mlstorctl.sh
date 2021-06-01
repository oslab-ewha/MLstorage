#!/bin/bash

function usage() {
	    cat <<EOF
Usage: mlstorctl -c -b <backing device> -s <nn size> <mlstor name>
       mlstorctl -d <mlstor name>
EOF
}

function get_sectors() {
    size=`lsblk -bln -o SIZE $1 | head -n 1`
    expr $size / 512
}

function create_mlstor() {
    if [[ ! -d /sys/kernel/stolearn-nn ]]; then
	echo "stolearn-nn kernel module not installed"
	exit 3
    fi
    echo "stolearn-nn attach $2" > /sys/kernel/stolearn-nn/mgmt
    cachesize=`expr $2 \* 8`
    sectors=`get_sectors $1`
    echo "0 $sectors stolearn-cache $1 /dev/stolearn-nn0 $cachesize" | dmsetup create $3
}

function delete_mlstor() {
    dmsetup remove $1
    echo "stolearn-nn detach 0" > /sys/kernel/stolearn-nn/mgmt
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
    create_mlstor $backdev $size $name
elif [[ -n $delete ]]; then
    delete_mlstor $name
else
    echo "You should run with -c or -d"
    exit 1
fi
