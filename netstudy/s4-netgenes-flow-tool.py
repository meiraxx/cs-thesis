import os
import errno
import argparse
import pandas as pd
from glob import glob
from pylib.pyaux.utils import Colors, OperatingSystem

from pylib.pynet import talker
from pylib.pynet import host
from pylib.pynet.netobject_utils import get_network_object_header

# quick work-around for terminal color in Windows
if os.name == "nt":
	from colorama import init
	init()
	del(init)

# ===================
# NetGenes Flows to:
# 	- Talkers
# 	- Hosts
# ===================
# Info:
# This script only exists because it is needed to study flow sets belonging to specified threat classes
# and threats, thus it is to be used for the netstudy context. It could also be improved to provide more
# independence in-between the different network objects, so that we can work with packets, flows, talkers
# and hosts in an independent manner.
# MAYBE-NOTE: we are also skeptical of the advantages of considering flows or talkers on hosts' view. Right
# now, talkers are used to build hosts, but hosts could also use the same talkers' statistics and just above
# the flows, which would mean that it would also be a flow-based feature, rather than talker-based

oparser = argparse.ArgumentParser(description='NetGenes extraction tool (from netgenes flows)')
# nargs="?" -> 1 file; nargs="+" -> multiple files
oparser.add_argument("flow_paths", metavar="Flow-File-Path", nargs='+', help="Input Flow CSV file", default="")
# COULD-TODO: could uncomment help and add custom argparser in the future
#oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
oparser.add_argument("-V", "--version", action="version", help="See NetGenes version", version="%(prog)s 1.0")
oparser.add_argument("--hr", "--human-readable", action="store_true", help="Get human readable output out of netgenes dir", dest='hreadable')
oparser.add_argument("-o", "--output-dir", help="output directory", dest='output_dir', default="s4-netgenes-by-dataset")
args = oparser.parse_args()

acceptable_independent_args = [args.hreadable,]
if args.flow_paths=="" and (not any(acceptable_independent_args)):
	print(Colors.RED + "You must input one or more Flow CSV files!" + Colors.ENDC, flush=True)
	exit()

ml_genes_dir = os.path.join("network-objects", "genes")

def output_net_genes(net_genes_generator_lst, l4_protocol, network_object_type, csv_output_dir, genes_dir, output_id):
	""" Output all NetObjects present on a PCAP file: biflows, bitalkers and bihosts, along with
	their respective genes (NetGenes): conceptual and statistical features. """
	def save_csv_file(net_genes_header_lst, net_genes_generator_lst, csv_filepath):
		# CSV Header
		net_genes_header_str = ",".join(net_genes_header_lst)
		# CSV Rows
		net_genes_str_lst = [",".join(net_genes) for net_genes in net_genes_generator_lst]
		net_genes_output = net_genes_header_str + "\n" + "\n".join(net_genes_str_lst)

		# Save CSV File
		f = open(csv_filepath, "w")
		f.write(net_genes_output)
		f.close()

	net_genes_header_lst = get_full_header_lst(l4_protocol, genes_dir, network_object_type)
	
	# CSV Directory
	os.makedirs(csv_output_dir, exist_ok=True)
	# Save NetGenes
	csv_filepath = os.path.join(csv_output_dir, "%s-%ss.csv"%(output_id, network_object_type))
	save_csv_file(net_genes_header_lst, net_genes_generator_lst, csv_filepath)

def _df_to_csv(df, output_fpath, operation):
	if operation == "write":
		df.to_csv(output_fpath, index=False)
	elif operation == "append":
		if os.path.isfile(output_fpath):
			df.to_csv(output_fpath, index=False, mode='a', header=False)
		else:
			df.to_csv(output_fpath, index=False)

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

def get_full_header_lst(l4_protocol, genes_dir, network_object_type):
	ipv4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4")
	ipv4_l4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4-l4")
	net_genes_header_lst = ""

	if l4_protocol.lower() == "udp":
		ipv4_udp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst
		net_genes_header_lst = ipv4_udp_net_genes_header_lst
	elif l4_protocol.lower() == "tcp":
		ipv4_tcp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst +\
			get_network_object_header(genes_dir, network_object_type, "ipv4-tcp")
		net_genes_header_lst = ipv4_tcp_net_genes_header_lst
	else:
		print("Unknown protocol '%s'"%(l4_protocol), flush=True)
		exit()

	# MAINTAIN PREVIOUS LABELS ON FLOWS
	# for general purposes, remove the following netstudy code
	if network_object_type == "biflow":
		net_genes_header_lst += ["Mapping", "Threat Class", "Threat", "Tool"]

	return net_genes_header_lst

def generate_netgenes_from_flow(flow_path):
	# RUN: python s4-netgenes-flow-tool.py <flow-file-path> --hr
	input_id = os.path.splitext(os.path.basename(flow_path))[0]
	output_id = input_id.replace("-biflows", "")
	l4_protocol = substring_between_str1_str2(input_id, "-ipv4-", "-biflows")
	# get flows' netgenes from the CSV to df
	df = pd.read_csv(flow_path)
	# for general purposes, remove netstudy columns
	# df = df.drop(['Threat Class', 'Threat', 'Tool', 'Mapping'], axis=1)

	# get netgenes from df to list
	ipv4_l4_biflow_genes_generator_lst = df.values.tolist()

	# convert typed netgenes to strings, also handling float-to-string conversion special case
	ipv4_l4_biflow_genes_generator_lst = [list(map(lambda x: str(round(x, 3)) if type(x)==float else str(x), net_genes)) for net_genes in ipv4_l4_biflow_genes_generator_lst]
	l4_biflow_ids = [net_genes[0] for net_genes in ipv4_l4_biflow_genes_generator_lst]
	# Save BiFlow Genes
	output_net_genes(ipv4_l4_biflow_genes_generator_lst, l4_protocol, "biflow", args.output_dir, ml_genes_dir, output_id)

	# -----------
	# Talkers
	# -----------
	# UniTalker Construction
	l4_unitalkers, l4_unitalker_ids = talker.build_unitalkers(ipv4_l4_biflow_genes_generator_lst, l4_biflow_ids)
	#n_ipv4_l4_unitalkers = len(l4_unitalker_ids)
	del(ipv4_l4_biflow_genes_generator_lst, l4_biflow_ids)

	# BiTalker Construction
	l4_bitalkers, l4_bitalker_ids = talker.build_bitalkers(l4_unitalkers, l4_unitalker_ids)
	n_ipv4_l4_bitalkers = len(l4_bitalker_ids)
	del(l4_unitalkers, l4_unitalker_ids)

	# BiTalker Genes Extraction
	ipv4_l4_bitalker_genes_generator_lst = talker.get_l3_l4_bitalker_gene_generators(\
		ml_genes_dir, l4_bitalkers, l4_bitalker_ids, l4_protocol=l4_protocol.upper())

	# Save BiTalker Genes
	output_net_genes(ipv4_l4_bitalker_genes_generator_lst, l4_protocol, "bitalker", args.output_dir, ml_genes_dir, output_id)

	# -----------
	# Hosts
	# -----------
	# BiHost Construction
	l4_bihosts, l4_bihost_ids = host.build_bihosts(ipv4_l4_bitalker_genes_generator_lst, l4_bitalker_ids)
	n_ipv4_l4_bihosts = len(l4_bihost_ids)
	del(ipv4_l4_bitalker_genes_generator_lst, l4_bitalker_ids)

	# BiHost Genes Extraction
	ipv4_l4_bihost_genes_generator_lst = host.get_l3_l4_bihost_gene_generators(\
		ml_genes_dir, l4_bihosts, l4_bihost_ids, l4_protocol=l4_protocol.upper())
	del(l4_bihosts, l4_bihost_ids)

	# Save BiHost Genes
	output_net_genes(ipv4_l4_bihost_genes_generator_lst, l4_protocol, "bihost", args.output_dir, ml_genes_dir, output_id)
	
	if args.hreadable:
		human_readable_input_dir = args.output_dir
		human_readable_genes_dir = "aux-s4-human-readable-genes"

		hr_biflow_header_lst = get_full_header_lst(l4_protocol, human_readable_genes_dir, "biflow")
		hr_bitalker_header_lst = get_full_header_lst(l4_protocol, human_readable_genes_dir, "bitalker")
		hr_bihost_header_lst = get_full_header_lst(l4_protocol, human_readable_genes_dir, "bihost")

		human_readable_output_dir = (args.output_dir).rstrip(os.sep) +  "-human-readable"
		mkdir_p(human_readable_output_dir)

		fname_header_dict = {
			"biflows.csv": hr_biflow_header_lst,
			"bitalkers.csv": hr_bitalker_header_lst,
			"bihosts.csv": hr_bihost_header_lst
		}
		for dname, dirs, files in os.walk(human_readable_input_dir):
			for fname in files:
				fpath = os.path.join(dname, fname)
				dict_key = fname.split("-")[-1]
				try:
					hr_header_lst = fname_header_dict[dict_key]
				except KeyError:
					print("Error, remove invalid file '%s' and start again."%(fname))
					exit()

				df = pd.read_csv(fpath)[hr_header_lst]

				no_ext_fname = os.path.splitext(os.path.basename(fname))[0]
				human_readable_output_fpath = os.path.join(human_readable_output_dir, "hr-%s.csv"%(no_ext_fname))
				_df_to_csv(df, human_readable_output_fpath, "write")


if __name__ == "__main__":
	# Preferable output directories:
	# s4-netgenes-by-dataset/ --> python s4-netgenes-flow-tool.py s3-netgenes-labeled-flows\by-dataset\*.csv 
	# s4-netgenes-by-dataset-by-threat/ --> python s4-netgenes-flow-tool.py s3-netgenes-labeled-flows\by-dataset-by-threat\*.csv -o s4-netgenes-by-dataset-by-threat
	# s4-netgenes-by-dataset-by-file/ --> python s4-netgenes-flow-tool.py s3-netgenes-labeled-flows\by-dataset-by-file\*.csv -o s4-netgenes-by-dataset-by-file
	mkdir_p(args.output_dir)
	# flow_paths is a list with the same number of items as the number of files you input, however JUST in 1 argument
	flow_paths = glob(args.flow_paths[0])
	for flow_path in flow_paths:
		print("Generating netgenes based on", flow_path, "file.")
		generate_netgenes_from_flow(flow_path)
	