import os
import errno
import pandas as pd
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

def handle_bad_data_df(df, dataset_name):
	if dataset_name == "CIC-IDS-2017":
		# PROTOCOLS: [0, 17, 6, nan]
		df.drop(
			df.index[
				(df["L3-L4 Protocol"].isnull()) | (df["Source IP"].isnull()) |
				(df["Source Port"].isnull()) | (df["Destination IP"].isnull()) |
				(df["Destination Port"].isnull()) | (df["Author Label"].isnull()) |
				(df["L3-L4 Protocol"].astype(float) == 0.0)
			], inplace = True)
		df = df.astype({"L3-L4 Protocol": int})
	elif dataset_name == "CTU-13":
		# LABELS: only interesting labels include "From-Botnet", since these are the ones in the PCAP
		# PROTOCOLS: ['rarp', 'unas', 'udp', 'ipv6', 'icmp', 'esp', 'tcp', 'ipx/spx', 'arp',
		# 'rtp', 'udt', 'llc', 'igmp', 'ipv6-icmp', 'rsvp', 'ipnip', 'pim', 'gre', 'rtcp']
		# Supported TCP protocol: tcp
		# Supported UDP protocol: udp
		# Supported L4+ protocols - UDP-based protocols: rtp, udt, rtcp
		# Supported L4+ protocols - TCP-based protocols: none present
		# Not supported ?? protocols: unas
		# Not supported L2 protocols: arp, rarp
		# Not supported L2+ protocols: llc
		# Not supported L3 protocols: ipv6, ipx
		# Not supported L3+ protocols: icmp, esp, igmp, ipv6-icmp, ipnip, pim, gre
		# Not supported L4 protocols: spx, rsvp
		# NOT SUPPORTED Protocols
		df.drop(
			df.index[
			(~df["Author Label"].str.contains('flow=From-Botnet', regex= True, na=False)) |
			(df["L3-L4 Protocol"].isnull()) | (df["Source IP"].isnull()) |
			(df["Source Port"].isnull()) | (df["Destination IP"].isnull()) |
			(df["Destination Port"].isnull()) | (df["Author Label"].isnull()) |
			(df["L3-L4 Protocol"] == "arp") | (df["L3-L4 Protocol"] == "rarp") |
			(df["L3-L4 Protocol"] == "llc") | (df["L3-L4 Protocol"] == "ipv6") |
			(df["L3-L4 Protocol"] == "ipx/spx") | (df["L3-L4 Protocol"] == "icmp") |
			(df["L3-L4 Protocol"] == "esp") | (df["L3-L4 Protocol"] == "igmp") |
			(df["L3-L4 Protocol"] == "ipv6-icmp") | (df["L3-L4 Protocol"] == "ipnip") |
			(df["L3-L4 Protocol"] == "pim") | (df["L3-L4 Protocol"] == "gre") |
			(df["L3-L4 Protocol"] == "rsvp") | (df["L3-L4 Protocol"] == "unas")
			], inplace = True)
		# SUPPORTED Protocols
		protocol_replacements = {
			'L3-L4 Protocol': {
				r'rtp': 'udp',
				r'rtcp': 'udp',
				r'udt': 'udp'
			}
		}
		df.replace(protocol_replacements, regex=True, inplace=True)
	return df

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
	Uses custom-separated files to organize normalized files with the following fields:
	"Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port",
	"Author Flow ID", "Author Label".
	"""
	input_dir = os.path.join("s0-author-labeled-flows", dataset_name)
	output_dir = os.path.join("s2-author-normalized-labeled-flows", dataset_name)
	mkdir_p(output_dir)
	interest_header_lst = interest_header.split(",")

	for dname, dirs, files in os.walk(input_dir):
		for fname in files:
			fpath = os.path.join(dname, fname)

			# handle bad-formatted data
			handle_bad_data(fpath, fname)

			# Note: for some reason I don't know, there are duplicate flows in some datasets:
			# (cic-flow-meter does not perform flow-id separation for different flows,
			# rather keeps it the same, and only uses the 5-minute timeout for flow separation,
			# but this does still not explain why there are duplicates)
			# e.g.:
			# 6,192.168.10.9,1038,192.168.10.3,88,BENIGN,192.168.10.3-192.168.10.9-88-1038-6
			# 6,192.168.10.3,88,192.168.10.9,1045,BENIGN,192.168.10.3-192.168.10.9-88-1045-6
			# ...

			"""
			Choose one:
			# get all unique rows into dataframe and escape unicoded fields
			df = pd.read_csv(fpath, encoding='unicode_escape')[interest_header_lst].drop_duplicates()
			# get all unique rows into dataframe
			df = pd.read_csv(fpath)[interest_header_lst].drop_duplicates()
			# get all rows into dataframe
			df = pd.read_csv(fpath)[interest_header_lst]
			"""
			# Drop duplicate dataset rows: may be flows, may be packets
			df = pd.read_csv(fpath)[interest_header_lst].drop_duplicates()

			# Get standard netgenes-defining flows and labels
			df = get_standard_flow_label_keys(df, interest_header_lst, has_author_flow_id)

			# Remove bad data from df
			df = handle_bad_data_df(df, dataset_name)

			# Drop duplicate netgenes-defined flows
			df = df.drop_duplicates()

			new_fname = fname_dict[fname]
			output_fpath = os.path.join(output_dir, "%s.csv"%(new_fname))
			if os.path.isfile(output_fpath):
				df.to_csv(output_fpath, index=False, mode='a', header=False)
			else:
				df.to_csv(output_fpath, index=False)

if __name__ == "__main__":
	"""
	Running this script requires the "s0-author-labeled-flows" directory, present in:
	- CIC-IDS-2017 labels ("GeneratedLabelledFlows" directory, <week-day name>-*.csv)
	- CTU-13 labels (<capture name>.binetflow files)
	"""
	# ------------
	# CIC-IDS-2017
	# ------------
	cicids2017_header_str = " Source IP, Source Port, Destination IP, Destination Port, Protocol, Label,Flow ID"
	cicids2017_fname_dict = {
		"Monday-WorkingHours.pcap_ISCX.csv": "Monday-WorkingHours", #Monday
		"Tuesday-WorkingHours.pcap_ISCX.csv": "Tuesday-WorkingHours", #Tuesday
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
	"""
	CTU-13 Issue 1:
	"Each of the scenarios in the dataset was processed to obtain different files.
	For privacy issues the complete pcap file containing all the background, normal
	and botnet data is not available." - this fact causes that our netgenes-generated
	flows are not as much as the author flows. Each scenario contains "the pcap file
	for the botnet capture only". We only extract "From-Botnet" labeled flows, since
	these are the only ones that we had also extracted with NetGenes.
	"""
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