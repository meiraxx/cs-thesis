import os
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


oparser = argparse.ArgumentParser(description='NetGenes extraction tool (from netgenes flows)')
oparser.add_argument("flow_path", metavar="Flow-File-Path", nargs="?", help="Input Flow CSV file", default="")
# COULD-TODO: could uncomment help and add custom argparser in the future
#oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
oparser.add_argument("-V", "--version", action="version", help="See NetGenes version", version="%(prog)s 1.0")
oparser.add_argument("-o", "--output-dir", help="output directory", dest='output_dir', default="flow-output")
args = oparser.parse_args()

if args.flow_path=="":
    print(Colors.RED + "Please give me a Flow CSV file as an input!" + Colors.ENDC, flush=True)
    exit()

genes_dir = "network-objects" + os.sep + "genes"

def output_net_genes(net_genes_generator_lst, l4_protocol, network_object_type, csv_output_dir, output_id):
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

if __name__ == "__main__":
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
	    genes_dir, tcp_bitalkers, tcp_bitalker_ids, l4_protocol="TCP")

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
	    genes_dir, tcp_bihosts, tcp_bihost_ids, l4_protocol="TCP")
	del(tcp_bihosts, tcp_bihost_ids)

	# Save TCP BiHost Genes
	output_net_genes(ipv4_tcp_bihost_genes_generator_lst, "TCP", "bihost", args.output_dir, output_id)