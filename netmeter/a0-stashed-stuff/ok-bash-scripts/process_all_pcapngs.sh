#!/bin/bash


pcapng_dir="data-files/pcapng"
if [[ -d "$pcapng_dir" ]]
then
	for pcapng_file in $(ls $pcapng_dir)
	do
		pcapng_fullpath="$pcapng_dir/$pcapng_file"
		# Verbose; Output = CSV
		./netmeter-tool.py $pcapng_fullpath -v -T CSV
	done
fi