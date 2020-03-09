#!/bin/bash

pcap_dir="data-files/pcap"
if [[ -d "$pcap_dir" ]]
then
	for pcap_file in $(ls $pcap_dir)
	do
		pcap_fullpath="$pcap_dir/$pcap_file"
		./netmeter-tool.py $pcap_fullpath -s -T CSV
	done
fi