# MLstorage (Machine Learning based Storage)

This project aims to support a solid state hybrid drive(SSHD) with an intelligent cache module,
which controls storage policy based on estimated IO access pattern.

## Build

- enter `kmod` directory and just `make`
  - The kernel module will be built against a current kernel version.
  - If you try to build with another version, please define `KSRC` environment variable
  - Linux source headers should be installed before build starts.
- If build succeeds, `kmod/mlstor.ko` will be generated.

## Run

- A MLstorage control script is provided as `script/mlstorctl.sh`.
- Prepare two partitions or devices for HDD and NVMe
  - Assumes `/dev/sdb4` and `/dev/nvme0n1p1`
  - root permission required
- create MLstorage device
  - Usage: `mlstorctl -c -b <backing device> -C <cache device> <mlstor name> `
  - eg) `script/mlstorctl -c -b /dev/sdb4 -C /dev/nvme01n1p1 mlstor_test
- create file system(ext4) on a MLstorage
   - `mkfs.ext4 /dev/mapper/mlstor_test`
   - `mkdir /data.mlstor`
   - `mount /dev/mapper/mlstor /data/.mlstor`
- Run benchmarks
	- We provide useful fio(Flexible I/O) scripts
	- `cd fio`
	- `./runfio.sh -t mlstor_test -o output_mlstor.txt`
	- `cat output_mlstor.txt`

<hr>
<sub>This project has been supported by ICT Research and Development Program of MSIP/IITP(Developing System Software Technologies for Emerging New Memory That Adaptively Learn Workload Characteristics) under Grant 2019-0-00074.</sub>
