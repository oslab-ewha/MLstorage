#!/bin/bash

function usage() {
	    cat <<EOF
Usage: mlstorctl -c -b <backing device> -C <cache device> <mlstor name>
       mlstorctl -d <mlstor name>
EOF
}

function get_sectors() {
    size=`lsblk -bln -o SIZE $1 | head -n 1`
    expr $size / 512
}

function create_mlstor() {
    sectors=`get_sectors $1`
    echo "0 $sectors stolearn-cache $1 $2" | dmsetup create $3 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "failed to create MLstorage: $3"
	exit 2
    fi
}

function delete_mlstor() {
    dmsetup info $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "MLstorage not found: $1"
	exit 3
    fi
    dmsetup remove $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "error: $1: failed to remove MLstorage: is it mounted?"
	exit 4
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo "mlstorctl should be run as root" 
    exit 2
fi

create=
delete=
backdev=
cachedev=
size=
while getopts "cdb:C:h" arg
do
    case $arg in
	c)
	    create=true
	    ;;
	d)
	    delete=true
	    ;;
	C)
	    cachedev=$OPTARG
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
    if [[ -z $cachedev ]]; then
	echo "caching device is required"
	exit 3
    fi
    create_mlstor $backdev $cachedev $name
elif [[ -n $delete ]]; then
    delete_mlstor $name
else
    echo "You should run with -c or -d"
    exit 1
fi
