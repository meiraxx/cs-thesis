import os
import errno
import sys
import argparse
import pandas as pd
from glob import glob

from collections import OrderedDict
import json

oparser = argparse.ArgumentParser(description='NetStudy - Labeled NetGenes Analyzer')
oparser.add_argument("netgenes_paths", metavar="NetGenes-Path", nargs="+", help="Input NetGenes path", default="")
oparser.add_argument("-s", "--output-stats", help="output stats", dest="output_stats")
#oparser.add_argument("-a", "--output-analysis", help="output analysis", dest="output_analysis")
oparser.add_argument("-a", "--output-analysis", action="store_true", help="output analysis", dest="output_analysis")
oparser.add_argument("-V", "--version", action="version", help="See NetStudy version", version="%(prog)s 1.0")
args = oparser.parse_args()

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
	# Preferable output directories:
	# s5-netgenes-data-stats-by-dataset-by-threat/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-threat\tcp\*.csv -s s5-netgenes-data-stats-by-dataset-by-threat\tcp
	# s5-netgenes-data-stats-by-dataset-by-file/ --> python s5-analyze-output.py s4-netgenes-by-dataset-by-file\tcp\*.csv -s s5-netgenes-data-stats-by-dataset-by-file\tcp
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
		#mkdir_p(args.output_analysis)

		def get_netwobjects_dict(netwobjects_df):
			#netwobjects_values = netwobjects_df.values.tolist()
			#netwobjects_header = netwobjects_df.columns.values.tolist()
			netwobjects_dict = netwobjects_df.to_dict("records", into=OrderedDict)
			#netwobjects_json = json.dumps(netwobjects_dict, indent=4)
			return netwobjects_dict

		def get_netwobject_filter(netwobject_dict, attack_type, netwobject_type):
			netwobject_filter_query = False
			if attack_type == "Port Scan":
				# USE rejected conns as filter
				if netwobject_type == "biflow":
					netwobject_filter_query = False
				elif netwobject_type == "bitalker":
					# USE biflow_fwd_n_unique_dst_ports
					netwobject_filter_query = \
						(netwobject_dict['biflow_dst_port'] == 444)
				elif netwobject_type == "bihost":
					netwobject_filter_query = False
			return netwobject_filter_query

		def filter_biflows_dict(biflows_dict, attack_type):
			filtered_biflows_dict = dict()
			for biflow_dict in biflows_dict:
				biflow_filter_query = get_netwobject_filter(biflow_dict, attack_type, "biflow")

				# yield biflow_dict if filter checks out, else yield None
				yield (biflow_dict if biflow_filter_query else None)

		biflows_dict = get_netwobjects_dict(flows_df)
		a = filter_biflows_dict(biflows_dict, "Port Scan")
		

		"""
		def filter_biflows_dict(biflows_dict, attack_type):
			filtered_biflows_dict = dict()
			for biflow_dict in biflows_dict:
				filter_biflow_dict(biflow_dict, attack_type)
		"""
		#filter_netwobject(flows_dict, )
		





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
	netgenes_paths = glob(args.netgenes_paths[0])
	for netgenes_path in netgenes_paths:
		base_protocol = "ipv4"
		l4_protocol = substring_between_str1_str2(netgenes_path.split(os.sep)[-1], "-ipv4-", "-biflows")
		flows_netgene_id = "%s-biflows.csv"%(l4_protocol)
		talkers_netgene_id = "%s-bitalkers.csv"%(l4_protocol)
		hosts_netgene_id = "%s-bihosts.csv"%(l4_protocol)
		if ("bitalkers" in netgenes_path) or ("bihosts" in netgenes_path):
			continue
		data_id = netgenes_path.split(os.sep)[-1].replace("-ipv4-%s-biflows.csv"%(l4_protocol),"")
		print("Generating", data_id, "netgenes stats.")
		analyze_output(netgenes_path, base_protocol, l4_protocol)