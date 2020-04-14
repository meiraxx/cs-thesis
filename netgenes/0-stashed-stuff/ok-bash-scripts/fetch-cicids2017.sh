#!/bin/bash

cic_ids_2017_dir="CIC-IDS-2017"
if [[ -d "$cic_ids_2017_dir" ]]; then
	echo "Error: directory $cic_ids_2017_dir already exists."
	exit 1
fi

# Download CIC-IDS-2017 dataset and rename CIC-IDS-2017 directory
echo "1. Downloading CIC-IDS-2017 dataset"
wget -e robots=off -r -nH --cut-dirs=2 --no-parent --reject="index.html*" http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/PCAPs/
mv "Dataset/PCAPs" "CIC-IDS-2017"
rmdir "Dataset"

# Change all CIC-IDS-2017 file exensions from PCAP to PCAPNG, since the dataset files are actually PCAPNG files
echo "2. Changing all CIC-IDS-2017 file exensions from PCAP to PCAPNG, since the dataset files are actually PCAPNG files"
download_dir="CIC-IDS-2017"
for f in $download_dir/*.pcap; do
	echo "$(basename $f) -> $(basename -- "$f" .pcap).pcapng"
    mv -- "$f" "$download_dir/$(basename -- "$f" .pcap).pcapng"
done

# Check downloaded dataset MD5s
echo "3. Checking CIC-IDS-2017 dataset md5s"
echo "<filename>: <supposed md5> == <actual md5>"
for f in $download_dir/*.pcapng; do
	supposed_file_md5=$(cut -d " " -f 1 $(echo "$f" | sed "s/\.pcapng/\.md5/g"))
	curr_file_md5=$(md5sum "$f" | cut -d " " -f 1)
	if [ "$supposed_file_md5" == "$curr_file_md5" ]; then
		echo "$(basename $f): $supposed_file_md5 == $curr_file_md5"
	else
		echo "$(basename $f): $supposed_file_md5 != $curr_file_md5"
	fi
done
