import os
import errno
import sys
import argparse
import pandas as pd
from glob import glob

oparser = argparse.ArgumentParser(description='NetStudy - Labeled NetGenes Analyzer')
oparser.add_argument("netgenes_paths", metavar="NetGenes-Path", nargs="+", help="Input NetGenes path", default="")
oparser.add_argument("-o", "--output-dir", help="output directory", dest='output_dir', default="s6-netgenes-data-stats")
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

# CONSTANTS
base_protocol = "ipv4"
flows_netgene_id = "tcp-biflows.csv"
talkers_netgene_id = "tcp-bitalkers.csv"
hosts_netgene_id = "tcp-bihosts.csv"

def analyze_output_stats(netgenes_path):
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

	curr_dname = args.output_dir + os.sep + flows_fname.rsplit("-ipv4")[0]
	mkdir_p(curr_dname)

	# FLOW
	# FILTERED-OUT FLOW FEATURES 
	# *eth_ipv4_data_len*
	# *eth_ipv4_data_len*

	# STATS: "25%", "50%", "75%", "std"
	flows_stats = flows_df.describe()
	flows_count = int(flows_stats.loc["count"].iloc[0])
	flows_stats = flows_stats.drop(["count"])
	flows_stats.to_csv(curr_dname + os.sep + flows_fname.rsplit(".csv")[0] + "-stats-" + str(flows_count) + ".csv", index = True)

	talkers_stats = talkers_df.describe()
	talkers_count = int(talkers_stats.loc["count"].iloc[0])
	talkers_stats = talkers_stats.drop(["count"])
	talkers_stats.to_csv(curr_dname + os.sep + talkers_fname.rsplit(".csv")[0] + "-stats-" + str(talkers_count) + ".csv", index = True)

	hosts_stats = hosts_df.describe()
	hosts_count = int(hosts_stats.loc["count"].iloc[0])
	hosts_stats = hosts_stats.drop(["count"])
	hosts_stats.to_csv(curr_dname + os.sep + hosts_fname.rsplit(".csv")[0] + "-stats-" + str(hosts_count) + ".csv", index = True)

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
	# Preferable output directories:
	# s6-netgenes-data-stats/ --> python s6-analyze-output.py 
	# s6-netgenes-data-stats-by-dataset-by-threat/ --> python s6-analyze-output.py s5-flow-output-by-dataset-by-threat\*.csv -o s6-netgenes-data-stats-by-dataset-by-threat
	# s6-netgenes-data-stats-by-dataset-by-file/ --> python s6-analyze-output.py s5-flow-output-by-dataset-by-file\*.csv -o s6-netgenes-data-stats-by-dataset-by-file
	netgenes_paths = glob(args.netgenes_paths[0])
	for netgenes_path in netgenes_paths:
		if ("bitalkers" in netgenes_path) or ("bihosts" in netgenes_path):
			continue
		print("Generating", netgenes_path.split(os.sep)[-1].replace("-ipv4-tcp-biflows.csv",""), "netgenes stats.")
		analyze_output_stats(netgenes_path)