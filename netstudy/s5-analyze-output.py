import os
import errno
import sys
import argparse
import pandas as pd
import math
from glob import glob

from collections import OrderedDict
import json

def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise

def substring_between_str1_str2(original_string, str1, str2):
	return original_string[original_string.find(str1)+len(str1):original_string.rfind(str2)]

def bitalker_id_to_unitalker_ids(bitalker_id):
	splitted_bitalker_id = bitalker_id.split("-")
	unitalker_fwd_id = "-".join([splitted_bitalker_id[0], splitted_bitalker_id[1], splitted_bitalker_id[2]])
	unitalker_bwd_id = "-".join([splitted_bitalker_id[1], splitted_bitalker_id[0], splitted_bitalker_id[2]])
	return (unitalker_fwd_id, unitalker_bwd_id)

def calc_metrics(tp, tn, fp, fn, total_results):
	# sanity check
	assert(total_results==tp+tn+fp+fn)

	# Class / Non-class results
	class_results = tp+fp
	non_class_results = tn+fn
	# Correct / Incorrect results
	correct_results = tp+tn
	incorrect_results = fp+fn
	# Positive / Negative results
	positive_results = tp+fn
	negative_results = tn+fp

	print("===========================")
	print("===========================")
	print("TP: %d"%(tp))
	print("TN: %d"%(tn))
	print("FP: %d"%(fp))
	print("FN: %d"%(fn))
	print("---------------------------")

	Sensitivity = None
	Miss_Rate = None
	Specificity = None
	Fallout = None
	Overall_Accuracy = None
	Precision = None
	F1_Score = None
	MCC = None

	if positive_results != 0:
		Sensitivity = round(float(tp)/float(positive_results), 5)
		# PS: 0.9964398037488992
		Miss_Rate = round(float(fn)/float(positive_results), 5)
		# PS: 0.003560196251100767

	if negative_results != 0:
		Specificity = round(float(tn)/float(negative_results), 5)
		# PS: 0.9996243664490461
		Fallout = round(float(fp)/float(negative_results), 5)
		# PS: 0.0003756335509538976

	if total_results != 0:
		Overall_Accuracy = round(float(correct_results)/float(total_results), 5)
		# PS: 0.9981695086696897

	if class_results != 0:
		Precision = round(float(tp)/float(class_results), 5)
		# PS: 0.9995520080764742

	if 2*tp+incorrect_results != 0:
		F1_Score = round(float(2*tp)/float(2*tp+incorrect_results), 5)
		# PS: 0.9979934795961759

	if math.sqrt((class_results)*(positive_results)*(negative_results)*(non_class_results)) != 0:
		MCC = round(float(tp*tn - fp*fn)/float(math.sqrt((class_results)*(positive_results)*(negative_results)*(non_class_results))), 5)
		# PS: 0.9963147248538874

	# LOVELY REPEATED CODE <3 happens when I'm in a hurry >:(
	if Sensitivity!=None:
		print("Sensitivity (TPR): %.3f%%"%(Sensitivity*100))
	else:
		print("Sensitivity (TPR): NA")

	if Specificity!=None:
		print("Specificity (TNR): %.3f%%"%(Specificity*100))
	else:
		print("Specificity (TNR): NA")

	if Fallout!=None:
		print("Fallout (FPR): %.3f%%"%(Fallout*100))
	else:
		print("Fallout (FPR): NA")

	if Miss_Rate!=None:
		print("Miss Rate (FNR): %.3f%%"%(Miss_Rate*100))
	else:
		print("Miss Rate (FNR): NA")

	if Overall_Accuracy!=None:
		print("Overall Accuracy: %.3f%%"%(Overall_Accuracy*100))
	else:
		print("Overall Accuracy: NA")

	if Precision!=None:
		print("Precision: %.3f%%"%(Precision*100))
	else:
		print("Precision: NA")

	if F1_Score!=None:
		print("F1-Score: %.3f%%"%(F1_Score*100))
	else:
		print("F1-Score: NA")

	if MCC!=None:
		print("MCC: %.3f%%"%(MCC*100))
	else:
		print("MCC: NA")
	print("===========================")
	print("===========================")
	return

def bitalker_filter(bitalker_ordered_dict, attack_type):
	bitalker_filter_query = False
	if attack_type == "Port Scan":
		# TR-1
		bitalker_filter_query = \
			(bitalker_ordered_dict["bitalker_fwd_biflow_n_unique_dst_ports"] > 100) or \
			(bitalker_ordered_dict["bitalker_bwd_biflow_n_unique_dst_ports"] > 100)
	return bitalker_filter_query

def filter_bitalkers_ordered_dict(bitalkers_ordered_dict_list, attack_type):
	filtered_bitalkers_list = list()
	filtered_out_bitalkers_list = list()
	for bitalker_ordered_dict in bitalkers_ordered_dict_list:
		if bitalker_filter(bitalker_ordered_dict, attack_type):
			filtered_bitalkers_list.append(bitalker_ordered_dict)
		else:
			filtered_out_bitalkers_list.append(bitalker_ordered_dict)
	
	return filtered_bitalkers_list, filtered_out_bitalkers_list

def biflow_filter(biflow_ordered_dict, attack_type, unitalker_ids_list):
	biflow_filter_query = False
	for i, unitalker_ids in enumerate(unitalker_ids_list):
		# FR-TR-Default
		fr_default = (biflow_ordered_dict["unitalker_id"] == unitalker_ids[0]) or (biflow_ordered_dict["unitalker_id"] == unitalker_ids[1])
		biflow_filter_query = biflow_filter_query or fr_default

	if attack_type == "Port Scan":
		# Port Scan FRs
		fr_1 = (biflow_ordered_dict["biflow_eth_ipv4_tcp_initiation_requested_connection"] == 1)
		fr_2 = (biflow_ordered_dict["biflow_eth_ipv4_tcp_initiation_two_way_handshake"] == 1)
		fr_2_1 = fr_2 and (biflow_ordered_dict["biflow_eth_ipv4_tcp_connection_rejected"] == 1)
		fr_2_2 = fr_2 and (biflow_ordered_dict["biflow_eth_ipv4_tcp_connection_established_half_duplex"] == 1)
		fr_2_2_1 = fr_2_2 and (biflow_ordered_dict["biflow_eth_ipv4_tcp_termination_abort"] == 1) and (biflow_ordered_dict["biflow_fwd_eth_ipv4_tcp_n_active_rst_flags"] > 0)
		fr_3 = (biflow_ordered_dict["biflow_eth_ipv4_tcp_initiation_three_way_handshake"] == 1) and (biflow_ordered_dict["biflow_bwd_n_packets"] == 1) and (biflow_ordered_dict["biflow_fwd_eth_ipv4_tcp_n_active_rst_flags"] > 0)
		
		# SIMPLE
		port_scan_biflow_filter1 = biflow_filter_query
		port_scan_biflow_filter2 = biflow_filter_query and fr_1
		port_scan_biflow_filter3 = biflow_filter_query and fr_2
		port_scan_biflow_filter4 = biflow_filter_query and fr_2_1
		port_scan_biflow_filter5 = biflow_filter_query and fr_2_2
		port_scan_biflow_filter6 = biflow_filter_query and fr_2_2_1
		port_scan_biflow_filter7 = biflow_filter_query and fr_3

		# COMPOUND
		port_scan_biflow_filter8 = biflow_filter_query and (fr_1 or fr_2)
		port_scan_biflow_filter9 = biflow_filter_query and (fr_1 or fr_2 or fr_3)

		biflow_filter_query = port_scan_biflow_filter9
	return biflow_filter_query

def filter_biflows_ordered_dict(biflows_ordered_dict_list, attack_type, unitalker_ids_list):
	filtered_biflows_list = list()
	filtered_out_bitalkers_list = list()
	for biflow_ordered_dict in biflows_ordered_dict_list:
		if biflow_filter(biflow_ordered_dict, attack_type, unitalker_ids_list):
			filtered_biflows_list.append(biflow_ordered_dict)
		else:
			filtered_out_bitalkers_list.append(biflow_ordered_dict)
	
	return filtered_biflows_list, filtered_out_bitalkers_list

def calc_bitalker_confusionMatrix(bitalker_positive_results, bitalker_negative_results, class_bitalker_ids):
	bitalker_tp = 0
	bitalker_fp = 0
	for bitalker in bitalker_positive_results:
		if bitalker["bitalker_id"] in class_bitalker_ids:
			bitalker_tp += 1
		else:
			bitalker_fp += 1

	bitalker_tn = 0
	bitalker_fn = 0
	for bitalker in bitalker_negative_results:
		if bitalker["bitalker_id"] in class_bitalker_ids:
			bitalker_fn += 1
		else:
			bitalker_tn += 1

	return bitalker_tp, bitalker_tn, bitalker_fp, bitalker_fn

def calc_biflow_confusionMatrix(biflow_positive_results, biflow_negative_results, label_text):
	biflow_tp = 0
	biflow_fp = 0
	for biflow in biflow_positive_results:
		if biflow["Threat Class"] == label_text:
			biflow_tp += 1
		else:
			biflow_fp += 1

	biflow_tn = 0
	biflow_fn = 0
	for biflow in biflow_negative_results:
		if biflow["Threat Class"] == label_text:
			biflow_fn += 1
		else:
			biflow_tn += 1

	return biflow_tp, biflow_tn, biflow_fp, biflow_fn

def test_bitalkers(talkers_df, attack_type, label_text, class_bitalker_ids):
	# Bi-Talker Filter
	bitalkers_ordered_dict_list = talkers_df.to_dict("records", into=OrderedDict)
	bitalker_positive_results, bitalker_negative_results = filter_bitalkers_ordered_dict(bitalkers_ordered_dict_list, attack_type)
	total_bitalkers = len(bitalkers_ordered_dict_list)
	print("Talkers:", total_bitalkers)
	print("Filtered Talkers:", len(bitalker_positive_results))

	bitalker_tp, bitalker_tn, bitalker_fp, bitalker_fn = calc_bitalker_confusionMatrix(bitalker_positive_results, bitalker_negative_results, class_bitalker_ids)
	calc_metrics(bitalker_tp, bitalker_tn, bitalker_fp, bitalker_fn, total_bitalkers)

	return bitalker_positive_results, bitalker_negative_results

def test_biflows(flows_df, attack_type, label_text, bitalker_positive_results):
	# Bi-Flow Filter
	unitalker_ids_list = [bitalker_id_to_unitalker_ids(bitalker["bitalker_id"]) for bitalker in bitalker_positive_results]
	biflows_ordered_dict_list = flows_df.to_dict("records", into=OrderedDict)
	biflow_positive_results, biflow_negative_results = filter_biflows_ordered_dict(biflows_ordered_dict_list, attack_type, unitalker_ids_list)
	total_biflows = len(biflows_ordered_dict_list)
	print("Flows:", total_biflows)
	print("Filtered Flows:", len(biflow_positive_results))

	biflow_tp, biflow_tn, biflow_fp, biflow_fn = calc_biflow_confusionMatrix(biflow_positive_results, biflow_negative_results, label_text)
	calc_metrics(biflow_tp, biflow_tn, biflow_fp, biflow_fn, total_biflows)

	return



def analyze_output(netgenes_path, base_protocol, l4_protocol):
	netgenes_dir = os.path.dirname(netgenes_path)
	netgenes_filename = os.path.basename(netgenes_path)
	dataset_id, netgenes_id = netgenes_filename.split("-%s-"%(base_protocol))

	if netgenes_id not in [flows_netgene_id, talkers_netgene_id, hosts_netgene_id]:
		print("An error occurred, the specified netgenes_id does not exist.")
		sys.exit(1)

	flows_fname = "%s-%s-%s"%(dataset_id, base_protocol, flows_netgene_id)
	talkers_fname = "%s-%s-%s"%(dataset_id, base_protocol, talkers_netgene_id)
	hosts_fname = "%s-%s-%s"%(dataset_id, base_protocol, hosts_netgene_id)

	flows_f = netgenes_dir + os.sep + flows_fname
	talkers_f = netgenes_dir + os.sep + talkers_fname
	hosts_f = netgenes_dir + os.sep + hosts_fname

	flows_df = pd.read_csv(flows_f)
	talkers_df = pd.read_csv(talkers_f)
	hosts_df = pd.read_csv(hosts_f)
	print("Flows Shape:", flows_df.shape)
	print("Talkers Shape:", talkers_df.shape)
	print("Hosts Shape:", hosts_df.shape)

	# "Stats": Statistic study
	# --------
	# STATS
	# --------
	# Output Stats - Preferable output directories:
	# s5-netgenes-data-stats-by-dataset-by-threat/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-threat\tcp\*.csv -s s5-netgenes-data-stats-by-dataset-by-threat\tcp
	# s5-netgenes-data-stats-by-dataset-by-file/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-file\tcp\*.csv -s s5-netgenes-data-stats-by-dataset-by-file\tcp
	# Output Analysis:
	# python s5-analyze-output.py s4-netgenes-by-dataset-by-file\tcp\*-biflows.csv -a
	if args.output_stats:
		mkdir_p(args.output_stats)

		flows_stats = flows_df.describe()
		flows_count = int(flows_stats.loc["count"].iloc[0])
		flows_stats = flows_stats.drop(["count"])
		flows_stats.to_csv(args.output_stats + os.sep + flows_fname.rsplit(".csv")[0] + "-stats-" + str(flows_count) + ".csv", index = True)

		talkers_stats = talkers_df.describe()
		talkers_count = int(talkers_stats.loc["count"].iloc[0])
		talkers_stats = talkers_stats.drop(["count"])
		talkers_stats.to_csv(args.output_stats + os.sep + talkers_fname.rsplit(".csv")[0] + "-stats-" + str(talkers_count) + ".csv", index = True)

		hosts_stats = hosts_df.describe()
		hosts_count = int(hosts_stats.loc["count"].iloc[0])
		hosts_stats = hosts_stats.drop(["count"])
		hosts_stats.to_csv(args.output_stats + os.sep + hosts_fname.rsplit(".csv")[0] + "-stats-" + str(hosts_count) + ".csv", index = True)

	# ----------
	# SUSPECTS
	# ----------
	# Preferable output directories:
	# s5-netgenes-data-stats-by-dataset-by-threat/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-threat\tcp\*.csv
	# s5-netgenes-data-stats-by-dataset-by-file/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-file\tcp\*.csv
	if args.output_analysis:
		# If generating a special case:
		# How to generate special cases (v2):
		# 1. Pick a file you want to edit
		# 2. Use Excel's "Get Data from Text/CSV", pick the flow file
		# (3). If there's a need to transform data types, hit "Transform Data" and,
		# in the Power Query Editor, modify types  and close&load the file
		# 4. Manually edit labels
		# (5). If there's a need to transform data types, format multiple cells and
		# define the right format before saving (e.g. 'yyyy-mm-dd hh:mm:ss.000' for dates)
		# 6. Copy bitalker and bihost equivalent dataset and add a "-v2" to its name
		# Friday whole day
		if dataset_id=="cicids2017-Friday-WorkingHours":
			# ---------
			# Port Scan
			# ---------
			attack_type = "Port Scan"
			label_text = "PortScan"
			friday_portscan_bitalker_ids = ["172.16.0.1-192.168.10.50-TCP"]

			bitalker_positive_results, bitalker_negative_results = test_bitalkers(talkers_df, attack_type, label_text, friday_portscan_bitalker_ids)
			test_biflows(flows_df, attack_type, label_text, bitalker_positive_results)
			# ----
			# DDoS
			# ----
			attack_type = "L4 Resource Exhaustion Denial of Service Attack"
			friday_ddos_bitalkers = ["172.16.0.1-192.168.10.50-TCP"]
			label_text = "DDoS"
		# Thursday special cases
		elif dataset_id=="cicids2017-Thursday-WorkingHours-v2":
			# ---------
			# Port Scan
			# ---------
			attack_type = "Port Scan"
			label_text = "PortScan"
			# "Port Scan" Thursday bi-talkers and uni-talkers (all relevant ones are forward, which helps us out):
			# 1st: "172.16.0.1-192.168.10.51-TCP"
			# 2nd: "192.168.10.8-192.168.10.12-TCP", "192.168.10.8-192.168.10.14-TCP", "192.168.10.8-192.168.10.15-TCP", "192.168.10.8-192.168.10.16-TCP", "192.168.10.8-192.168.10.17-TCP", "192.168.10.8-192.168.10.19-TCP", "192.168.10.8-192.168.10.25-TCP", "192.168.10.8-192.168.10.5-TCP", "192.168.10.8-192.168.10.50-TCP", "192.168.10.8-192.168.10.51-TCP", "192.168.10.8-192.168.10.9-TCP"
			# Need to label all flows as "Port Scan", except the first 5 flows
			# Need to filter flows from 2nd bi-talkers that are:
			# 	- from time "18:05:14" to time "18:44:35" to label as Port Scan (70885)
			#	- source ports 1266-3215 (mostly connect/version scans, apparently) and 33264-65243 (70092)
			# 	- not targeting destination port 5060, which is "SIP" benign traffic (70018)
			thursday_portscan_bitalker_ids = ["172.16.0.1-192.168.10.51-TCP", "192.168.10.8-192.168.10.12-TCP", "192.168.10.8-192.168.10.14-TCP", "192.168.10.8-192.168.10.15-TCP", "192.168.10.8-192.168.10.16-TCP", "192.168.10.8-192.168.10.17-TCP", "192.168.10.8-192.168.10.19-TCP", "192.168.10.8-192.168.10.25-TCP", "192.168.10.8-192.168.10.5-TCP", "192.168.10.8-192.168.10.50-TCP", "192.168.10.8-192.168.10.51-TCP", "192.168.10.8-192.168.10.9-TCP"]
			#bitalker_positive_results = [{"bitalker_id": "172.16.0.1-192.168.10.51-TCP"}]

			bitalker_positive_results, bitalker_negative_results = test_bitalkers(talkers_df, attack_type, label_text, thursday_portscan_bitalker_ids)
			test_biflows(flows_df, attack_type, label_text, bitalker_positive_results)
		else:
			print("Dataset ID '%s' not recognized"%(dataset_id))



	"""
	portscan_flows = list()
	print(flows_header)
	flows_header
	for i, flow_value in enumerate(flows_values):
		print(flow_value)
	"""
	# talkers_df
	# hosts_df


	"""
	PORTSCAN SUSPECTS
	Dataset:
	- 158930 CICIDS2017 flows --> 158675 5-tuple NetGenes flows --> 159679 6-tuple NetGenes flows
	> Tier 1 Detection - <Threat> EXISTENCE: USING BITALKER AND BIHOST
	>> Look for...
	>>> Portscan Talkers:
		- High n_biflows per Talker
		- High n_unique_dst_ports per Talker
		- High 
	>>> Portscan Hosts:
		- ...

	> Tier 2 Detection - <Threat> FLOW-BY-FLOW DETECTION: USING BIFLOWS
	>> In Tier 1 results, look for...
	>>> Portscans:
		- High STD in the BiFlow DST_PORT
	"""

	"""
	# Thresholds
	talker_n_dst_ports = talkers_df['bitalker_any_biflow_n_unique_dst_ports']>100
	filtered_talkers_df = talkers_df[talker_n_dst_ports]
	"""

	"""
	talkers_values = talkers_df.values.tolist()
	talkers_header = talkers_df.columns.values.tolist()
	# Suspects
	portscan_talkers = list()
	print(talkers_header)
	for i, talker_value in enumerate(talkers_values):
		talker_value[0]
		print(talker_value)
	"""

# MAIN
if __name__ == "__main__":
	oparser = argparse.ArgumentParser(description='NetStudy - Labeled NetGenes Analyzer')
	oparser.add_argument("netgenes_paths", metavar="NetGenes-Path", nargs="+", help="Input NetGenes path", default="")
	oparser.add_argument("-s", "--output-stats", help="output stats", dest="output_stats")
	#oparser.add_argument("-a", "--output-analysis", help="output analysis", dest="output_analysis")
	oparser.add_argument("-a", "--output-analysis", action="store_true", help="output analysis", dest="output_analysis")
	oparser.add_argument("-V", "--version", action="version", help="See NetStudy version", version="%(prog)s 1.0")
	args = oparser.parse_args()
	# testing with ISCX-IDS-2012: go to http://205.174.165.80/CICDataset/ISCX-IDS-2012/Dataset/
	netgenes_paths = glob(args.netgenes_paths[0])
	for netgenes_path in netgenes_paths:
		print(netgenes_path)
		base_protocol = "ipv4"
		l4_protocol = substring_between_str1_str2(netgenes_path.split(os.sep)[-1], "-ipv4-", "-biflows")
		flows_netgene_id = "%s-biflows.csv"%(l4_protocol)
		talkers_netgene_id = "%s-bitalkers.csv"%(l4_protocol)
		hosts_netgene_id = "%s-bihosts.csv"%(l4_protocol)
		if ("bitalkers" in netgenes_path) or ("bihosts" in netgenes_path):
			# ignore bitalker and bihost files
			continue
		data_id = netgenes_path.split(os.sep)[-1].replace("-ipv4-%s-biflows.csv"%(l4_protocol),"")
		if args.output_stats:
			print("Generating", data_id, "netgenes stats.")
		elif args.output_analysis:
			print("Generating", data_id, "netgenes analysis.")
		analyze_output(netgenes_path, base_protocol, l4_protocol)