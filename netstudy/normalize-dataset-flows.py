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
	# Note: In "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", replace en-dash
	# with a real hyphen
	if fname == "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
		replace_string_in_file(fpath, u"\u2013", "-")

def get_standard_flow_label_keys(df, interest_header_lst, has_author_flow_id):
	source_ip_txt = interest_header_lst[0]
	orig_source_ip_txt = "Source IP"
	source_port_txt = interest_header_lst[1]
	orig_source_port_txt = "Source Port"
	destination_ip_txt = interest_header_lst[2]
	orig_destination_ip_txt = "Destination IP"
	destination_port_txt = interest_header_lst[3]
	orig_destination_port_txt = "Destination Port"
	protocol_txt = interest_header_lst[4]
	orig_protocol_txt = "L3-L4 Protocol"
	label_header_txt = interest_header_lst[5]
	author_label_header_txt = "Author Label"
	if has_author_flow_id:
		flow_id_txt = interest_header_lst[6]
		author_flow_id_txt = "Author Flow ID"

	orig_keys = [orig_protocol_txt, orig_source_ip_txt, orig_source_port_txt,
	orig_destination_ip_txt, orig_destination_port_txt, author_label_header_txt]

	replaceable_keys = [protocol_txt, source_ip_txt, source_port_txt,
	destination_ip_txt, destination_port_txt, label_header_txt]

	if has_author_flow_id:
		orig_keys.append(author_flow_id_txt)
		replaceable_keys.append(flow_id_txt)

	replacement_dict = dict(zip(replaceable_keys, orig_keys))
	df.rename(columns=replacement_dict, inplace=True)

	return df[orig_keys]

def normalize_flow_based_datasets(dataset_name, interest_header, fname_dict, has_author_flow_id):
	"""
	Supported datasets: CIC-IDS-2017 and CTU-13
	Uses custom-separated files to organize label-separated files with the following fields:
	"Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port",
	"Author Flow ID", "Author Label".
	"""
	input_dir = os.path.join("author-labeled-flows", dataset_name)
	output_dir = os.path.join("normalized-labeled-flows", dataset_name)
	mkdir_p(output_dir)
	interest_header_lst = interest_header.split(",")

	for dname, dirs, files in os.walk(input_dir):
		for fname in files:
			fpath = os.path.join(dname, fname)

			# handle bad-formatted data
			handle_bad_data(fpath, fname)

			# get all unique flows into dataframe
			#df = pandas.read_csv(fpath, index_col=False, encoding='unicode_escape')[interest_header_lst].drop_duplicates()
			df = pandas.read_csv(fpath, index_col=False)[interest_header_lst].drop_duplicates()

			df = get_standard_flow_label_keys(df, interest_header_lst, has_author_flow_id)

			new_fname = fname_dict[fname]
			output_fpath = os.path.join(output_dir, "%s.csv"%(new_fname))
			if os.path.isfile(output_fpath):
				df.to_csv(output_fpath, index=False, mode='a', header=False)
			else:
				df.to_csv(output_fpath, index=False)

if __name__ == "__main__":
	# ------------
	# CIC-IDS-2017
	# ------------
	cicids2017_header_str = " Source IP, Source Port, Destination IP, Destination Port, Protocol, Label,Flow ID"
	#cicids2017_header_str = " Source IP, Source Port, Destination IP, Destination Port, Protocol, Label"
	cicids2017_fname_dict = {
		"Monday-WorkingHours.pcap_ISCX.csv": "Monday-WorkingHours", #Monday
		"Tuesday-WorkingHours.pcap_ISCX.csv":"Tuesday-WorkingHours", #Tuesday
		"Wednesday-workingHours.pcap_ISCX.csv": "Wednesday-WorkingHours", #Wednesday
		"Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "Thursday-WorkingHours", #Thursday
		"Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "Thursday-WorkingHours", #Thursday
		"Friday-WorkingHours-Morning.pcap_ISCX.csv": "Friday-WorkingHours", #Friday
		"Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "Friday-WorkingHours", #Friday
		"Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "Friday-WorkingHours" #Friday
	}
	normalize_flow_based_datasets("CIC-IDS-2017", cicids2017_header_str, cicids2017_fname_dict, has_author_flow_id=True)

	# ------
	# CTU-13
	# ------
	ctu13_header_str = "SrcAddr,Sport,DstAddr,Dport,Proto,Label"
	ctu13_fname_dict = {
		"capture20110810.binetflow": "botnet-capture-20110810-neris", #1
		"capture20110811.binetflow":"botnet-capture-20110811-neris", #2
		"capture20110812.binetflow": "botnet-capture-20110812-rbot", #3
		"capture20110815.binetflow": "botnet-capture-20110815-rbot-dos", #4
		"capture20110815-2.binetflow": "botnet-capture-20110815-fast-flux", #5
		"capture20110815-3.binetflow": "botnet-capture-20110815-fast-flux-2", #13
		"capture20110816.binetflow": "botnet-capture-20110816-donbot", #6
		"capture20110816-2.binetflow": "botnet-capture-20110816-sogou", #7
		"capture20110816-3.binetflow": "botnet-capture-20110816-qvod", #8
		"capture20110817.binetflow": "botnet-capture-20110817-bot", #9
		"capture20110818.binetflow": "botnet-capture-20110818-bot", #10
		"capture20110818-2.binetflow": "botnet-capture-20110818-bot-2", #11
		"capture20110819.binetflow": "botnet-capture-20110819-bot" #12
	}
	normalize_flow_based_datasets("CTU-13", ctu13_header_str, ctu13_fname_dict, has_author_flow_id=False)
