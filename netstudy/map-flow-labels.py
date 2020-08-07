import os
import errno
import pandas
import numpy as np

def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise

def replace_string_in_file(file_path, original_string, new_string):
	with open(file_path, "r") as f:
		s = f.read()

	s = s.replace(original_string, new_string)

	with open(file_path, "w") as f:
		f.write(s)

def handle_bad_data(fpath, fname):
	""" Any data that needs to be fixed in an input dataset can be fixed here"""
	if fname == "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
		replace_string_in_file(fpath, u"\u2013", "-")

def map_dataset(dataset_name, interest_header):
	"""
	Supported datasets: CIC-IDS-2017 and CTU-13
	1. Uses custom-separated files to organize label-separated files (label must be the last field
	specified in the interest_header)
	2. For each supported dataset, it transposes author flows into NetGenes flow, talker and host
	IDs and adds this information to the label-separated files, with the following fields:
	"Original Flow ID", "NetGenes Flow ID", "Threat Class", "Threat", "Tool"
	"""
	input_dir = os.path.join("author-flow-labels", dataset_name)
	output_dir = os.path.join("flow-labels-mapping", dataset_name)
	mkdir_p(output_dir)
	interest_header_lst = interest_header.split(",")

	flow_mapping_dict = dict()
	for dname, dirs, files in os.walk(input_dir):
		for fname in files:
			fpath = os.path.join(dname, fname)

			# handle bad-formatted data
			handle_bad_data(fpath, fname)

			# get all unique flows into dataframe
			#df = pandas.read_csv(fpath, index_col=False, encoding='unicode_escape')[interest_header_lst].drop_duplicates()
			df = pandas.read_csv(fpath, index_col=False)[interest_header_lst].drop_duplicates()
			label_header_txt = interest_header_lst[-1]

			# get all labels
			labels = [x[0] for x in df[[label_header_txt]].drop_duplicates().values]

			for label in labels:
				labeled_df = df[df[label_header_txt] == label]
				output_fpath = os.path.join(output_dir, "%s.csv"%(label))
				try:
					if os.path.isfile(output_fpath):
						labeled_df.to_csv(output_fpath, index=False, mode='a', header=False)
					else:
						labeled_df.to_csv(output_fpath, index=False)
				except UnicodeDecodeError:
					print("[!] Error parsing file '%s' due to 'utf-8'" %(fpath))
					continue

if __name__ == "__main__":
	# ------------
	# CIC-IDS-2017
	# ------------
	cicids2017_header_str = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Label"
	# Note: In "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", replace weird character
	# by a real hyphen ("-")
	map_dataset("CIC-IDS-2017", cicids2017_header_str)

	# ------
	# CTU-13
	# ------

