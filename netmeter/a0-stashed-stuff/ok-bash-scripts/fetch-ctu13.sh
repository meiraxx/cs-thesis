#!/bin/bash

ctu13_dir="CTU-13"
if [[ -d "$ctu13_dir" ]]; then
	echo "Error: directory $ctu13_dir already exists."
	exit 1
fi

mkdir "$ctu13_dir"
# Fetch compressed CTU-13 Dataset, containing 13 botnet scenarios
wget --no-check-certificate https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2

tar -xf CTU-13-Dataset.tar.bz2 --directory "$ctu13_dir"

mv $ctu13_dir/CTU-13-Dataset/* "$ctu13_dir"
rmdir "$ctu13_dir/CTU-13-Dataset"
rm "CTU-13-Dataset.tar.bz2"