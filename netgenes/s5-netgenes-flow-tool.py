import os
import errno
import argparse
import pandas as pd

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
oparser.add_argument("flow_path", metavar="Flow-File-Path", nargs="?", help="Input Flow CSV file", default="")
# COULD-TODO: could uncomment help and add custom argparser in the future
#oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
oparser.add_argument("-V", "--version", action="version", help="See NetGenes version", version="%(prog)s 1.0")
oparser.add_argument("--hr", "--human-readable", action="store_true", help="Get human readable output out of flow-output dir", dest='hreadable')
oparser.add_argument("-o", "--output-dir", help="output directory", dest='output_dir', default="s5-flow-output")
args = oparser.parse_args()

acceptable_independent_args = [args.hreadable,]
if args.flow_path=="" and (not any(acceptable_independent_args)):
	print(Colors.RED + "Please give me a Flow CSV file as an input!" + Colors.ENDC, flush=True)
	exit()

ml_genes_dir = os.path.join("network-objects", "genes")

def output_net_genes(net_genes_generator_lst, l4_protocol, network_object_type, csv_output_dir, genes_dir, output_id):
	""" Output all NetObjects present on a PCAP file: biflows, bitalkers and bihosts, along with
	their respective genes (NetGenes): conceptual and statistical features. """
	ipv4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4")
	ipv4_l4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4-l4")
	net_genes_header_lst = ""

	if l4_protocol == "UDP":
		ipv4_udp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst
		net_genes_header_lst = ipv4_udp_net_genes_header_lst
	elif l4_protocol == "TCP":
		ipv4_tcp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst +\
			get_network_object_header(genes_dir, network_object_type, "ipv4-tcp")
		net_genes_header_lst = ipv4_tcp_net_genes_header_lst
	else:
		print("Unknown protocol '%s'"%(l4_protocol), flush=True)
		exit()

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
	# CSV Directory
	os.makedirs(csv_output_dir, exist_ok=True)
	# Save NetGenes
	csv_filepath = os.path.join(csv_output_dir, "%s-ipv4-%s-%ss.csv"%(output_id, l4_protocol.lower(), network_object_type))
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

def get_full_header_lst(l4_protocol, genes_dir, network_object_type):
	ipv4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4")
	ipv4_l4_net_genes_header_lst = get_network_object_header(genes_dir, network_object_type, "ipv4-l4")
	net_genes_header_lst = ""

	if l4_protocol == "UDP":
		ipv4_udp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst
		net_genes_header_lst = ipv4_udp_net_genes_header_lst
	elif l4_protocol == "TCP":
		ipv4_tcp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst +\
			get_network_object_header(genes_dir, network_object_type, "ipv4-tcp")
		net_genes_header_lst = ipv4_tcp_net_genes_header_lst
	else:
		print("Unknown protocol '%s'"%(l4_protocol), flush=True)
		exit()

	return net_genes_header_lst

if __name__ == "__main__":
	"""
	output_id = os.path.splitext(os.path.basename(args.flow_path))[0]

	# get flows' netgenes from the CSV to df
	df = pd.read_csv(args.flow_path)
	# get netgenes from df to list
	ipv4_tcp_biflow_genes_generator_lst = df.values.tolist()
	#print(ipv4_tcp_biflow_genes_generator_lst)
	#exit()

	# convert typed netgenes to strings, also handling float-to-string conversion special case
	ipv4_tcp_biflow_genes_generator_lst = [list(map(lambda x: str(round(x, 3)) if type(x)==float else str(x), net_genes)) for net_genes in ipv4_tcp_biflow_genes_generator_lst]
	tcp_biflow_ids = [net_genes[0] for net_genes in ipv4_tcp_biflow_genes_generator_lst]
	# Save TCP BiFlow Genes
	output_net_genes(ipv4_tcp_biflow_genes_generator_lst, "TCP", "biflow", args.output_dir, output_id)

	# -----------
	# TCP Talkers
	# -----------
	# TCP UniTalker Construction
	tcp_unitalkers, tcp_unitalker_ids = talker.build_unitalkers(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)
	#n_ipv4_tcp_unitalkers = len(tcp_unitalker_ids)
	del(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)

	# TCP BiTalker Construction
	tcp_bitalkers, tcp_bitalker_ids = talker.build_bitalkers(tcp_unitalkers, tcp_unitalker_ids)
	n_ipv4_tcp_bitalkers = len(tcp_bitalker_ids)
	del(tcp_unitalkers, tcp_unitalker_ids)

	# TCP BiTalker Genes Extraction
	ipv4_tcp_bitalker_genes_generator_lst = talker.get_l3_l4_bitalker_gene_generators(\
		ml_genes_dir, tcp_bitalkers, tcp_bitalker_ids, l4_protocol="TCP")

	# Save TCP BiTalker Genes
	output_net_genes(ipv4_tcp_bitalker_genes_generator_lst, "TCP", "bitalker", args.output_dir, output_id)

	# -----------
	# TCP Hosts
	# -----------
	# TCP BiHost Construction
	tcp_bihosts, tcp_bihost_ids = host.build_bihosts(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)
	n_ipv4_tcp_bihosts = len(tcp_bihost_ids)
	del(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

	# TCP BiHost Genes Extraction
	ipv4_tcp_bihost_genes_generator_lst = host.get_l3_l4_bihost_gene_generators(\
		ml_genes_dir, tcp_bihosts, tcp_bihost_ids, l4_protocol="TCP")
	del(tcp_bihosts, tcp_bihost_ids)

	# Save TCP BiHost Genes
	output_net_genes(ipv4_tcp_bihost_genes_generator_lst, "TCP", "bihost", args.output_dir, output_id)
	"""
	#TODO
	if args.hreadable:
		human_readable_input_dir = args.output_dir
		human_readable_genes_dir = "s5-human-readable-genes"

		hr_biflow_header_lst = get_full_header_lst("TCP", human_readable_genes_dir, "biflow")
		hr_bitalker_header_lst = get_full_header_lst("TCP", human_readable_genes_dir, "bitalker")
		hr_bihost_header_lst = get_full_header_lst("TCP", human_readable_genes_dir, "bihost")

		human_readable_output_dir = "s5-human-readable-flow-output"
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