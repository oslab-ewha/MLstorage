#!/bin/bash

function usage() {
	    cat <<EOF
Usage: dmcache -c -b <backing device> -C <cache device> <dmcache name>
       dmcache -d <dmcache name>
EOF
}

# cache block size in sector
blocksize=512

function create_dmcache() {
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

    sectors_cachemeta=`expr \( 4194304 + \( 16 \* $size_caching \) / \( $blocksize \* 512 \) \) / 512`
    echo "0 $sectors_cachemeta linear $2 0" | dmsetup create $3-cachemeta
    if [[ $? -ne 0 ]]; then
	exit 3
    fi
    dd if=/dev/zero of=/dev/mapper/$3-cachemeta >& /dev/null

    sectors_caching=`expr $size_caching / 512`
    sectors_cachepool=`expr $sectors_caching - $sectors_cachemeta`
    echo "0 $sectors_cachepool linear $2 $sectors_cachemeta" | dmsetup create $3-cachepool
    if [[ $? -ne 0 ]]; then
	dmsetup remove $3-cachemeta
	exit 3
    fi

    echo "0 $sectors_backing cache /dev/mapper/$3-cachemeta /dev/mapper/$3-cachepool $1 $blocksize 1 writeback default 0" | dmsetup create $3
    if [[ $? -ne 0 ]]; then
	echo "failed to create dmcache: $3"
	dmsetup remove $3-cachemeta
	dmsetup remove $3-cachepool
	exit 4
    fi
}

function delete_dmcache() {
    dmsetup info $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "dmcache not found: $1"
	exit 3
    fi
    dmsetup remove $1 >& /dev/null
    if [[ $? -ne 0 ]]; then
	echo "error: $1: failed to remove dmcache: is it mounted?"
	exit 4
    fi
    dmsetup remove $1-cachepool
    dmsetup remove $1-cachemeta
}

if [[ $EUID -ne 0 ]]; then
    echo "dmcache should be run as root" 
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
    create_dmcache $backdev $cachedev $name
elif [[ -n $delete ]]; then
    delete_dmcache $name
else
    echo "You should run with -c or -d"
    exit 1
fi
