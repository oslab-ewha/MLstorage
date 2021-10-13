#!/bin/bash

function usage() {
    cat <<EOF
Usage: runfio.sh [options] [<fio script>]
options>
 -o <output path>: output file path for summary(required)
 -t <type>: sshd or mlstor
 -h: this message

  all *.fio would be executed if no script is privieded
EOF
}

FIO=fio
N_TRYS=3

MNT_SSHD=${MNT_SSHD:-/data.sshd}
MNT_MLSTOR=${MNT_MLSTOR:-/data.mlstor}

trap cleanup 1 2 15

while getopts "o:t:h" arg
do
    case $arg in
	o)
	    output=$OPTARG
	    ;;
	t)
	    type=$OPTARG
	    ;;
	h)
	    usage
	    exit 0
	    ;;
	*)
	    usage
	    exit 1
    esac
done

shift `expr $OPTIND - 1`

function cleanup() {
    if [[ -n $tmpfile ]]; then
       rm -f $tmpfile
    fi
}

function get_fio_perf() {
    tmpfile=.fio.out.$$
    DIR=$dir $FIO $script | tee $tmpfile
    if [[ $? -ne 0 ]]; then
	echo "ERROR: failed to run fio"
	exit 1
    fi
    res=`tail -n 1 .fio.out.$$ | grep -Ewo 'bw=[[:digit:].]*(GiB|MiB|KiB|B)' | grep -Ewo '[[:digit:].]*(GiB|MiB|KiB|B)'`
    rm -f $tmpfile
    tmpfile=
    if [[ -z $res ]]; then
	echo "ERROR: unexpected fio result"
	exit 2
    fi
    case $res in
	*GiB)
	    v=$((${res%???} * 1024))
	    ;;
	*MiB)
	    v=${res%???}
	    ;;
	*)
	    v=1
	    ;;
    esac
}

function run_fio_multl() {
    sum=0
    for i in `seq $N_TRYS`
    do
	get_fio_perf
	sum=`echo "scale=3; $sum + $v" | bc`
    done
    v=`echo "scale=3; $sum / $N_TRYS" | bc`
}

function run_fio() {
    type=$1
    if [[ $type == 'sshd' ]]; then
	dir=$MNT_SSHD
    else
	dir=$MNT_MLSTOR
    fi
    cat <<EOF

**************************************
$type
**************************************

EOF
    run_fio_multl
}

function run_fios() {
    cat <<EOF

**************************************************
Run benchmark test for $script
**************************************************

EOF
    if [[ -z $type ]]; then
	run_fio sshd
	perf_sshd=$v
	run_fio mlstor
	perf_mlstor=$v

	perfup=`echo "scale=10; (($perf_mlstor - $perf_sshd) / $perf_sshd) * 100" | bc`
	printf "%16s %17s %17s %15.1f\n" $script $perf_sshd $perf_mlstor $perfup >> $output
    else
	run_fio $type
	perf=$v

	printf "%16s %17s %17s\n" $script $perf >> $output
    fi
}

if [[ -z $output ]]; then
    echo "output option is required"
    exit 1
fi

if [[ -z $type ]]; then
    printf "#%15s %17s %17s %15s\n" script 'sshd(MiB/s)' 'MLStorage(MiB/s)' 'PerfUp(%)' >> $output
elif [[ $type = "sshd" ]]; then
    printf "#%15s %17s\n" script 'sshd(MiB/s)' >> $output
else
    printf "#%15s %17s\n" script 'MLStorage(MiB/s)' >> $output
fi

if [[ $# -eq 0 ]]; then
    for script in `ls *.fio`
    do
	run_fios
    done
else
    script=$1
    run_fios
fi
