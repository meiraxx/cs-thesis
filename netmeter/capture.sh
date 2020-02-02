#!/bin/bash
set -e

if [ $# -ne 5 ]
then
	echo "Usage: capture <interface> <duration> <pcap filepath>"
	exit
fi

interface="$1"
cap_duration="$2"
pcap_filepath="$3"

trap 'rm "${pcap_filepath}";exit;' SIGINT

echo "Capturing on ${interface}..."
tshark -i "$interface" -a "duration:${cap_duration}" -w "${pcap_filepath}" -F pcap &> /dev/null
echo "Capture ended."
