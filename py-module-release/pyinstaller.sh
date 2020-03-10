#!/bin/bash

if [ "$1" == "" ]; then
	echo "Error: You must provide the python script's path as a command-line argument."
	exit 1
fi

py_path="$1"
script_name=$(basename -- "$py_path" .py)
if [[ -d "$script_name" ]]; then
	echo "Error: directory $script_name already exists."
	exit 1
fi

# Installing/upgrading pyinstaller
pip install --upgrade pyinstaller

# Running pyinstaller
pyinstaller "$py_path"

# Organizing stuff
mkdir $script_name
mv "build/" "dist/" "$script_name.spec" "$script_name"