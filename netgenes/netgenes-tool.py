#!/usr/bin/env python3

"""
This script is meant to output "bihosts" (ipX), "bitalkers" (ipX-ipY) and "biflows"
(ipX-portA-ipY-portB-protocol_stack-inner_sep_counter), which are network objects,
and their respective conceptual and statistical features to build a dataset. These
network objects (NetObjects) are meant to perform a logical packet aggregation having
a bidirectional view at all times, hence the 'bi' prefix. For simplicity, the generated
conceptual and statistical NetObject features are called, in their combination, NetGenes.
The netgenes-tool will take a PCAP as an input and will output NetGenes in a specified output format.
NetGenes is the first of the four (1/4) main tasks of my thesis.

AUTHORSHIP:
Joao Meira <joao.meira.cs@gmail.com>

"""

# ===============================================================
# OSI-layer protocols: https://en.wikipedia.org/wiki/List_of_network_protocols_(OSI_model)
# L0 (physical methods of propagation): Copper, Fiber, Wireless
# NetGenes Protocols
# L1-protocols: Ethernet (Physical Layer)
# L2-protocols: **Ethernet**, ++ARP++
# L2plus-protocols: ++LLC++
# L3-protocols: **IPv4 (IP-4)**, IPv6 (IP-41)
# L3plus-protocols: ++ICMPv4 (IP-1)++, ++IGMPv4 (IP-2)++, ICMPv6 (IP-58), GRE (IP-47)
# L4-protocols: **TCP (IP-6)**, ++UDP (IP-17)++
# SOME REFS:
# https://en.wikipedia.org/wiki/EtherType; https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
# [L2] ARP: https://tools.ietf.org/html/rfc826
# [L2plus] LLC: https://tools.ietf.org/html/rfc1103
# [L3plus] ICMP: https://tools.ietf.org/html/rfc792
# [L3plus] IGMP: https://tools.ietf.org/html/rfc1112
# [L4] UDP https://tools.ietf.org/html/rfc768
# [L4] TCP: https://tools.ietf.org/html/rfc793
# ===============================================================

# =================
# Library Imports |
# =================

# ===============================
# Standard Python Library Modules
# ===============================
import time
import argparse
import os

# for debugging code
import code

# ===============================
# Custom Auxiliary Python Modules
# ===============================
from pylib.pyaux.utils import Colors, OperatingSystem
from pylib.pyaux.utils import datetime_to_unixtime, unixtime_to_datetime
from pylib.pyaux.utils import make_header_string

from pylib.pynet.netobject_utils import get_network_object_header
from pylib.pynet import packet
from pylib.pynet import flow
from pylib.pynet import talker
from pylib.pynet import host

# ====================
# NetGenes Arguments |
# ====================
class NetGenesArgs:
    class HelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            if prefix is None:
                prefix = 'Usage: '
            return super(HelpFormatter, self).add_usage(usage, actions, groups, prefix)

    def __init__(self):
        def check_and_print_help(args, help_message):
            """Local helper function to check if help should be printed and, if so, print it."""
            if args.print_help:
                print(help_message, flush=True)
                exit()
            elif args.pcap_path=="":
                help_message = help_message.replace("PCAP-File-Path", Colors.YELLOW + "PCAP-File-Path <-- " + Colors.ENDC + \
                    Colors.RED + "Please give me a PCAP file as an input!" + Colors.ENDC)
                print(help_message, flush=True)
                exit()

        def verify_output_type(args):
            """Local helper function to verify output type: csv, mongo, etc."""
            supported_output_types = ("csv",)
            if args.output_type not in supported_output_types:
                print("[!] Specified output type", Colors.RED + args.output_type + Colors.ENDC,
                    "is not a valid output type. Valid output types:"  + Colors.BLUE,
                    ",".join(supported_output_types) + Colors.ENDC, flush=True)
                exit()

        oparser = argparse.ArgumentParser(prog="NetGenes", description="Description: NetGene extraction tool", \
            epilog="For any enquiries, please contact me at joao[dot]meira[dot]cs[at]gmail[dot]com", add_help=False)
        oparser.add_argument("pcap_path", metavar="PCAP-File-Path", nargs="?", help="Input PCAP file", default="")
        oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
        oparser.add_argument("-V", "--version", action="version", help="See NetGenes version", version="%(prog)s 1.0")
        oparser.add_argument("-s", "--safe-check", action="store_true", help="Perform safe checks", dest="safe_check")
        oparser.add_argument("-d", metavar="Debug Verbose", help="Specify debug output: 1 (packet), 2 (flow)", dest="debug")
        oparser.add_argument("-v", "--verbose", action="store_true", help="Verbose output", dest="verbose")
        oparser.add_argument("-D", metavar="Data Directory", help="Specify data directory: store inputs (e.g. PCAP) and outputs (e.g. CSV)", dest="data_dir", default="data-files")
        oparser.add_argument("-T", metavar="Output Type", help="Specify output type: csv, json, ...", dest="output_type", type=str.lower, default="csv")
        optional_args_noreq_header = "Optional arguments (does not require other arguments)"
        optional_args_noreq_repr = ":\n  -h, -H, --help     See this help message\n  -V, --version      See NetGenes version"
        optional_args_req_header = "Optional arguments (requires a PCAP file)"
        oparser._positionals.title = "Positional arguments"
        oparser._optionals.title = optional_args_noreq_header
        help_message = oparser.format_help()
        help_message = help_message.replace(optional_args_noreq_header + optional_args_noreq_repr,
            optional_args_noreq_header + optional_args_noreq_repr + "\n\n" + optional_args_req_header)
        help_message = help_message.replace("[PCAP-File-Path]", "PCAP-File-Path")[:-1]
        args = oparser.parse_args()

        check_and_print_help(args, help_message)
        verify_output_type(args)
        self.args = args

# ==================
# NetGenes Globals |
# ==================
class NetGenesGlobals:
    def __init__(self, args):
        self.pcapng_files_dir = args.data_dir + os.sep + "pcapng"
        self.csv_files_dir = args.data_dir + os.sep + "csv"
        # csv output dir is only created when needed
        self.csv_output_dir = self.csv_files_dir + os.sep + os.path.splitext(os.path.basename(args.pcap_path))[0]
        self.genes_dir = "network-objects" + os.sep + "genes"

# =====================
# Auxiliary Functions |
# =====================

def print_supported_protocols_info():
    print(make_header_string("NetGenes Supported Protocols", "-", "-", big_header_factor=2), flush=True)
    print("[+] Layer 1: Ethernet", flush=True)
    print("[+] Layer 2: Ethernet", flush=True)
    print("[+] Layer 3: IPv4", flush=True)
    print("[-] Layer 3+: ICMPv4, IGMPv4", flush=True)
    print("[+] Layer 4: TCP, UDP", flush=True, end="\n\n")

def print_netgenes_info():
    print(make_header_string("NetGenes by Protocol Stacks and NetObjects", "-", "-", big_header_factor=2), flush=True)
    # minus 4 to remove biflow_id, bitalker_id, biflow_any_first_packet_time and biflow_any_last_packet_time
    ipv4_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4")) - 4
    ipv4_l4_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4-l4"))
    ipv4_tcp_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4-tcp"))
    print("[+] IPv4 BiFlow Genes:", ipv4_biflow_genes_count, "BiFlow Genes", flush=True)
    print("[+] IPv4-UDP BiFlow Genes:", \
        ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count, "BiFlow Genes", flush=True)
    print("[+] IPv4-TCP BiFlow Genes:", \
        ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count + ipv4_tcp_biflow_genes_count, "BiFlow Genes", flush=True)
    # minus 5 to remove bitalker_id, bihost_fwd_id, bihost_bwd_id, bitalker_any_first_biflow_initiation_time
    # and bitalker_any_last_biflow_termination_time
    ipv4_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4")) - 5
    ipv4_l4_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4-l4"))
    ipv4_tcp_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4-tcp"))
    print("[+] IPv4 BiTalker Genes:", ipv4_bitalker_genes_count, "BiTalker Genes", flush=True)
    print("[+] IPv4-UDP BiTalker Genes:", \
        ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count, "BiTalker Genes", flush=True)
    print("[+] IPv4-TCP BiTalker Genes:", \
        ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count + ipv4_tcp_bitalker_genes_count, "BiTalker Genes", \
        flush=True)
    # minus 3 to remove bihost_id, bihost_first_bitalker_initiation_time
    # and bihost_first_bitalker_termination_time
    ipv4_bihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bihost", "ipv4")) - 3
    ipv4_l4_bihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bihost", "ipv4-l4"))
    ipv4_tcp_bihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bihost", "ipv4-tcp"))
    print("[+] IPv4 BiHost Genes:", ipv4_bihost_genes_count, "BiHost Genes", flush=True)
    print("[+] IPv4-UDP BiHost Genes:", \
        ipv4_bihost_genes_count + ipv4_l4_bihost_genes_count, "BiHost Genes", flush=True)
    print("[+] IPv4-TCP BiHost Genes:", \
        ipv4_bihost_genes_count + ipv4_l4_bihost_genes_count + ipv4_tcp_bihost_genes_count, "BiHost Genes", \
        flush=True)
    
def output_net_genes(net_genes_generator_lst, l4_protocol, network_object_type):
    """ Output all NetObjects present on a PCAP file: biflows, bitalkers and bihosts, along with
    their respective genes (NetGenes): conceptual and statistical features. """

    ipv4_net_genes_header_lst = get_network_object_header(netgenes_globals.genes_dir, network_object_type, "ipv4")
    ipv4_l4_net_genes_header_lst = get_network_object_header(netgenes_globals.genes_dir, network_object_type, "ipv4-l4")
    net_genes_header_lst = ""

    if l4_protocol == "UDP":
        ipv4_udp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst
        net_genes_header_lst = ipv4_udp_net_genes_header_lst
    elif l4_protocol == "TCP":
        ipv4_tcp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst +\
            get_network_object_header(netgenes_globals.genes_dir, network_object_type, "ipv4-tcp")
        net_genes_header_lst = ipv4_tcp_net_genes_header_lst
    else:
        print("Unknown protocol '%s'"%(l4_protocol), flush=True)
        exit()

    
    if args.output_type == "csv":
        def save_csv_file(net_genes_header_lst, net_genes_generator_lst, csv_filename):
            # CSV Header
            net_genes_header_str = "|".join(net_genes_header_lst)
            # CSV Rows
            net_genes_str_lst = ["|".join(net_genes) for net_genes in net_genes_generator_lst]
            net_genes_output = net_genes_header_str + "\n" + "\n".join(net_genes_str_lst)

            # Save CSV File
            f = open(netgenes_globals.csv_output_dir + os.sep + csv_filename, "w")
            f.write(net_genes_output)
            f.close()
        # CSV Directory
        os.makedirs(netgenes_globals.csv_output_dir, exist_ok=True)
        # Save NetGenes
        save_csv_file(net_genes_header_lst, net_genes_generator_lst, "ipv4-%s-%ss.csv"%(l4_protocol.lower(), network_object_type))

# ===================
# Main Program Flow |
# ===================
def generate_network_objets(input_file):
    """ Build all NetObjects: packets, flows, bitalkers and hosts;
        and extract their respective NetGenes """

    if args.verbose:
        run_init_time = time.time()
        print(make_header_string("1. Packet Construction", "=", "=", big_header_factor=2), flush=True)

    # =========
    # Packets |
    # =========
    packet_genes = packet.build_packets(input_file, args)

    # =======
    # Flows |
    # =======
    if args.verbose:
        print(make_header_string("2. Layer-3 Flow Construction and Layer-4 Separation", "=", "=", big_header_factor=2), flush=True)

    # =======================
    # L3 Unidirectional Flows
    # =======================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.1. Layer-3 Unidirectional Flows: IPv4"), flush=True)

    l3_uniflows, l3_uniflow_ids = flow.build_l3_uniflows(packet_genes)
    del(packet_genes)

    if args.verbose:
        n_preserved_packets = sum([len(l3_uniflows[l3_uniflow_id]) for l3_uniflow_id in l3_uniflow_ids])
        print("[+] Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] Flows detected:" + Colors.GREEN, len(l3_uniflow_ids), "IPv4 UniFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ======================
    # L3 Bidirectional Flows
    # ======================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.2. Layer-3 Bidirectional Flows: IPv4"), flush=True)

    l3_biflows, l3_biflow_ids = flow.build_l3_biflows(l3_uniflows, l3_uniflow_ids)
    del(l3_uniflows, l3_uniflow_ids)

    if args.verbose:
        n_preserved_packets = sum([len(l3_biflows[l3_biflow_id]) for l3_biflow_id in l3_biflow_ids])
        print("[+] IPv4 Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] IPv4 BiFlows detected:" + Colors.GREEN, len(l3_biflows), "IPv4 BiFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # =========================
    # L3/L4 Bidirectional Flows
    # =========================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.3. Bidirectional Flows: IPv4-UDP, IPv4-TCP"), flush=True)

    udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features,\
        n_disconected_rfc793_packets = flow.build_l4_biflows(l3_biflows, l3_biflow_ids, args.debug)
    n_ipv4_udp_biflows = len(udp_biflows)
    n_ipv4_tcp_biflows = len(tcp_biflows)
    n_preserved_udp_packets = sum([len(udp_biflows[udp_biflow_id]) for udp_biflow_id in udp_biflow_ids])
    n_preserved_tcp_packets = sum([len(tcp_biflows[tcp_biflow_id]) for tcp_biflow_id in tcp_biflow_ids])
    del(l3_biflows, l3_biflow_ids)

    if args.verbose:
        print("[+] IPv4-UDP Packets preserved:", n_preserved_udp_packets, "IPv4-UDP OK Packets", flush=True)
        print("[+] IPv4-TCP Packets preserved:", n_preserved_tcp_packets, "IPv4-TCP OK Packets", flush=True)
        print("[+] IPv4-TCP Packets disconected:", n_disconected_rfc793_packets, "IPv4-TCP DCed Packets", flush=True)
        print("[+] IPv4-UDP BiFlows detected:" + Colors.GREEN, n_ipv4_udp_biflows, "IPv4-UDP BiFlows" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiFlows detected:" + Colors.GREEN, n_ipv4_tcp_biflows, "IPv4-TCP BiFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ======================================================================
    # NetObject Construction and NetGene Extraction: organizing juicy data |
    # ======================================================================
    if args.verbose:
        print(make_header_string("3. Layer-3/Layer-4 NetObject Construction and NetGene Extraction", "=", "=", big_header_factor=2), flush=True)

    # ================================================================================================================= #
    # =======================================================UDP======================================================= #
    # ================================================================================================================= #
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("3.1. IPv4-UDP NetObject Construction and NetGene Extraction"), flush=True)

    # ---------
    # UDP Flows
    # ---------
    # UDP BiFlow Extraction
    ipv4_udp_biflow_genes_generator_lst = flow.get_l3_l4_biflow_gene_generators(\
        netgenes_globals.genes_dir, udp_biflows, udp_biflow_ids,\
        l4_conceptual_features=None, l4_protocol="UDP", verbose=args.verbose)
    del(udp_biflows)

    # Save UDP BiFlow Genes
    output_net_genes(ipv4_udp_biflow_genes_generator_lst, "UDP", "biflow")

    # -----------
    # UDP Talkers
    # -----------
    # UDP UniTalker Construction
    udp_unitalkers, udp_unitalker_ids = talker.build_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)
    #n_ipv4_udp_unitalkers = len(udp_unitalker_ids)
    del(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)

    # UDP BiTalker Construction
    udp_bitalkers, udp_bitalker_ids = talker.build_bitalkers(udp_unitalkers, udp_unitalker_ids)
    n_ipv4_udp_bitalkers = len(udp_bitalker_ids)
    del(udp_unitalkers, udp_unitalker_ids)

    # UDP BiTalker Genes Extraction
    ipv4_udp_bitalker_genes_generator_lst = talker.get_l3_l4_bitalker_gene_generators(\
        netgenes_globals.genes_dir, udp_bitalkers, udp_bitalker_ids, l4_protocol="UDP")
    del(udp_bitalkers)

    # Save UDP BiTalker Genes
    output_net_genes(ipv4_udp_bitalker_genes_generator_lst, "UDP", "bitalker")

    # ---------
    # UDP Hosts
    # ---------
    # UDP BiHost Construction
    udp_bihosts, udp_bihost_ids = host.build_bihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)
    n_ipv4_udp_bihosts = len(udp_bihost_ids)
    del(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)

    # UDP BiHost Genes Extraction
    ipv4_udp_bihost_genes_generator_lst = host.get_l3_l4_bihost_gene_generators(\
        netgenes_globals.genes_dir, udp_bihosts, udp_bihost_ids, l4_protocol="UDP")
    del(udp_bihosts, udp_bihost_ids)

    # Save UDP BiHost Genes
    output_net_genes(ipv4_udp_bihost_genes_generator_lst, "UDP", "bihost")

    if args.verbose:
        print("[+] IPv4-UDP Packets detected:" + Colors.GREEN, n_preserved_udp_packets, "IPv4-UDP BiFlows" + Colors.ENDC, flush=True)
        print("[+] IPv4-UDP BiFlows detected:" + Colors.GREEN, n_ipv4_udp_biflows, "IPv4-UDP BiFlows" + Colors.ENDC, flush=True)
        #print("[+] IPv4-UDP UniTalkers detected:" + Colors.GREEN, n_ipv4_udp_unitalkers, "IPv4-UDP UniTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-UDP BiTalkers detected:" + Colors.GREEN, n_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-UDP BiHosts detected:" + Colors.GREEN, n_ipv4_udp_bihosts, "IPv4-UDP BiHosts" + Colors.ENDC, flush=True)
        print("[T] Calculated and saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================================================================================================= #
    # =======================================================UDP======================================================= #
    # ================================================================================================================= #

    # ================================================================================================================= #
    # =======================================================TCP======================================================= #
    # ================================================================================================================= #
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("3.2. IPv4-TCP NetObject Construction and NetGene Extraction"), flush=True)

    # ---------
    # TCP Flows
    # ---------
    # TCP BiFlow Extraction
    ipv4_tcp_biflow_genes_generator_lst = flow.get_l3_l4_biflow_gene_generators(\
        netgenes_globals.genes_dir, tcp_biflows, tcp_biflow_ids,\
        l4_protocol="TCP", l4_conceptual_features=rfc793_tcp_biflow_conceptual_features, verbose=args.verbose)
    del(tcp_biflows, rfc793_tcp_biflow_conceptual_features)

    # Save TCP BiFlow Genes
    output_net_genes(ipv4_tcp_biflow_genes_generator_lst, "TCP", "biflow")

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
        netgenes_globals.genes_dir, tcp_bitalkers, tcp_bitalker_ids, l4_protocol="TCP")

    # Save TCP BiTalker Genes
    output_net_genes(ipv4_tcp_bitalker_genes_generator_lst, "TCP", "bitalker")

    # -----------
    # TCP Hosts
    # -----------
    # TCP BiHost Construction
    tcp_bihosts, tcp_bihost_ids = host.build_bihosts(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)
    n_ipv4_tcp_bihosts = len(tcp_bihost_ids)
    del(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

    # TCP BiHost Genes Extraction
    ipv4_tcp_bihost_genes_generator_lst = host.get_l3_l4_bihost_gene_generators(\
        netgenes_globals.genes_dir, tcp_bihosts, tcp_bihost_ids, l4_protocol="TCP")
    del(tcp_bihosts, tcp_bihost_ids)

    # Save TCP BiHost Genes
    output_net_genes(ipv4_tcp_bihost_genes_generator_lst, "TCP", "bihost")

    if args.verbose:
        print("[+] IPv4-TCP Packets detected:" + Colors.GREEN, n_preserved_tcp_packets, "IPv4-TCP BiFlows" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiFlows detected:" + Colors.GREEN, n_ipv4_tcp_biflows, "IPv4-TCP BiFlows" + Colors.ENDC, flush=True)
        #print("[+] IPv4-TCP UniTalkers detected:" + Colors.GREEN, n_ipv4_tcp_unitalkers, "IPv4-TCP UniTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiTalkers detected:" + Colors.GREEN, n_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiHosts detected:" + Colors.GREEN, n_ipv4_tcp_bihosts, "IPv4-TCP BiHosts" + Colors.ENDC, flush=True)
        print("[T] Calculated and saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================================================================================================= #
    # =======================================================TCP======================================================= #
    # ================================================================================================================= #

    # ==========
    # FINISHED |
    # ==========
    if args.verbose:
        print(make_header_string("Total Extraction Time", "=", "=", big_header_factor=2), flush=True)
        print("[T] Script took" + Colors.YELLOW, round(time.time() - run_init_time, 3), "seconds" +\
            Colors.ENDC, "to complete", flush=True, end="\n\n")

def run():
    #os.makedirs(netgenes_globals.pcapng_files_dir, exist_ok=True)
    os.makedirs(netgenes_globals.csv_files_dir, exist_ok=True)

    print(make_header_string("NetGenes I/O Info", "=", "=", big_header_factor=2), flush=True)
    print("[+] Input PCAP file:"  + Colors.BLUE, args.pcap_path + Colors.ENDC, flush=True)
    pcap_size_bytes = os.path.getsize(args.pcap_path)
    pcap_size_str = OperatingSystem.get_size_str(pcap_size_bytes)
    if args.output_type == "csv":
        print("[+] Output CSV directory:", Colors.BLUE + netgenes_globals.csv_output_dir +\
            Colors.ENDC, flush=True)
    print("[+] Parsing and working on", Colors.BLUE + pcap_size_str + Colors.ENDC, "of data. Please wait.", flush=True)

    if args.verbose:
        print("\n")
        print_supported_protocols_info()
        print_netgenes_info()
        print("\n")

    with open(args.pcap_path, "rb") as input_file:
        generate_network_objets(input_file)

    if args.output_type == "csv":
        csv_output_dir_size = OperatingSystem.get_dir_size(netgenes_globals.csv_output_dir)
        csv_size_str = OperatingSystem.get_size_str(csv_output_dir_size)
        print("[+] Network-object (BiFlows, BiTalkers and BiHosts) genes extracted:" + Colors.BLUE,
            csv_size_str + Colors.ENDC, flush=True, end="\n\n")

# Reading Command-Line Output:
# [!]: Error Information
# [+]: Normal Information
# [T]: Time Information
# [D]: Debug Information
if __name__ == "__main__":
    args = NetGenesArgs().args
    netgenes_globals = NetGenesGlobals(args)
    run()
