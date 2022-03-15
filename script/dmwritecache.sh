#!/bin/bash

function usage() {
	    cat <<EOF
Usage: dmwritecache -c -b <backing device> -C <cache device> <dmwritecache name>
       dmwritecache -d <dmwritecache name>
EOF
}

# cache block size in sector
blocksize=512

function create_dmwritecache() {
    sectors_backing=`blockdev --getsz $1 2> /dev/null`
    size_caching=`blockdev --getsize64 $2 2> /dev/null`
    if [[ -z $sectors_backing ]]; then
	echo "failed to get device size: $1"
	exit 2
    fi
    if [[ -z $size_caching ]]; then
	echo "failed to get device size: $2"
	exit 2
    fi

    sectors=`expr $sectors_backing / 4096 \* 4096`
    echo "0 $sectors writecache s $1 $2 4096 0" | dmsetup create $3
    if [[ $? -ne 0 ]]; then
	echo "failed to create dmwritecache: $3"
	exit 4
    fi
}

function delete_dmwritecache() {
    dmsetup info $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "dmwritecache not found: $1"
	exit 3
    fi
    dmsetup remove $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "error: $1: failed to remove dmwritecache: is it mounted?"
	exit 4
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo "dmwritecache should be run as root" 
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
    create_dmwritecache $backdev $cachedev $name
elif [[ -n $delete ]]; then
    delete_dmwritecache $name
else
    echo "You should run with -c or -d"
    exit 1
fi