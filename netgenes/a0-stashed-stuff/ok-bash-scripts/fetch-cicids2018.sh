#!/bin/bash

cse_cic_ids_2018_dir="CSE-CIC-IDS-2018"

if [[ -d "$cse_cic_ids_2018_dir" ]]; then
	echo "Error: directory $cse_cic_ids_2018_dir already exists."
	exit 1
fi

# Download CSE-CIC-IDS-2018 dataset
echo "1. Downloading CSE-CIC-IDS-2018 dataset"
mkdir CSE-CIC-IDS-2018
aws s3 sync --no-sign-request --region eu-west-3 "s3://cse-cic-ids2018/" CSE-CIC-IDS-2018

# Remove useless dir
mv CSE-CIC-IDS-2018/Original\ Network\ Traffic\ and\ Log\ data/* $cse_cic_ids_2018_dir
rmdir "CSE-CIC-IDS-2018/Original Network Traffic and Log data"

# Discard log files and organize zip files containing PCAPs
cd "$cse_cic_ids_2018_dir"
for dir in *; do
	rm "$dir/logs.zip"
	# check if DIR is still not empty
	if [ "$(ls -A $dir)" ]; then
		mv "$dir/pcap.zip" "$dir/$dir.zip"
		mv "$dir/$dir.zip" "./"
	fi

	rmdir "$dir"
done

# Extract PCAPs and organize them into directories
for f in *.zip; do
	unzip "$f"
	mv "pcap" "$(basename -- $f .zip)"
	rm "$f"
done

cd ".."


