#!/usr/bin/env python3

"""
This script is meant to output "unihosts" (ipX), "bitalkers" (ipX-ipY) and "biflows"
(ipX-portA-ipY-portB-protocol_stack-inner_sep_counter), which are network objects,
and their respective conceptual and statistical features to build a dataset. These
network objects are meant to perform a logical packet aggregation having a bidirectional
view at all times, hence the 'bi' prefix. For simplicity, the generated conceptual and
statistical network object features are called, in their combination, network object genes.
NetMeter will take a PCAP as an input and will output NetGenes in a specified output format.
NetMeter is the first of the four (1/4) main tasks of my thesis.

AUTHORSHIP:
Joao Meira <joao.meira.cs@gmail.com>

"""

# ===============================================================
# OSI-layer protocols: https://en.wikipedia.org/wiki/List_of_network_protocols_(OSI_model)
# L0 (physical methods of propagation): Copper, Fiber, Wireless
# NetMeter Protocols
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
import socket, ipaddress
import datetime, time
import argparse
import os, sys
from collections import OrderedDict
# for debugging code
import code

# ==========================
# Third-party Python Modules
# ==========================
try:
    import dpkt
    import numpy as np
    from dpkt.compat import compat_ord
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# ===============================
# Custom Auxiliary Python Modules
# ===============================
from pyaux.cterminal import Colors

# ====================
# NetMeter Arguments |
# ====================
class NetMeterArgs:
    class HelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            if prefix is None:
                prefix = 'Usage: '
            return super(HelpFormatter, self).add_usage(usage, actions, groups, prefix)

    def __init__(self):
        def check_and_print_help(args, help_message):
            """Local helper function to check if help should be printed and, if so, print it."""
            if args.print_help:
                print(help_message, file=sys.stderr, flush=True)
                sys.exit(1)
            elif args.pcap_path=="":
                help_message = help_message.replace("PCAP-File-Path", Colors.YELLOW + "PCAP-File-Path <-- " + Colors.ENDC + \
                    Colors.RED + "Please give me a PCAP file as an input!" + Colors.ENDC)
                print(help_message, file=sys.stderr, flush=True)
                sys.exit(1)

        def verify_output_type(args):
            """Local helper function to verify output type: csv, mongo, etc."""
            supported_output_types = ("csv",)
            if args.output_type not in supported_output_types:
                print("[!] Specified output type", Colors.RED + args.output_type + Colors.ENDC,
                    "is not a valid output type. Valid output types:"  + Colors.BLUE,
                    ",".join(supported_output_types) + Colors.ENDC, flush=True)
                sys.exit(1)

        oparser = argparse.ArgumentParser(prog="NetMeter", description="Description: NetGene extraction tool", \
            epilog="For any enquiries, please contact me at joao[dot]meira[dot]cs[at]gmail[dot]com", add_help=False)
        oparser.add_argument("pcap_path", metavar="PCAP-File-Path", nargs="?", help="Input PCAP file", default="")
        oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
        oparser.add_argument("-V", "--version", action="version", help="See NetMeter version", version="%(prog)s 1.0")
        oparser.add_argument("-s", "--safe-check", action="store_true", help="Perform safe checks", dest="safe_check")
        oparser.add_argument("-d", metavar="Debug Verbose", help="Specify debug output: 1 (packet), 2 (flow)", dest="debug")
        oparser.add_argument("-v", "--verbose", action="store_true", help="Verbose output", dest="verbose")
        oparser.add_argument("-D", metavar="Data Directory", help="Specify data directory: store inputs (e.g. PCAP) and outputs (e.g. CSV)", dest="data_dir", default="data-files")
        oparser.add_argument("-T", metavar="Output Type", help="Specify output type: csv, json, ...", dest="output_type", type=str.lower, default="csv")
        optional_args_noreq_header = "Optional arguments (does not require other arguments)"
        optional_args_noreq_repr = ":\n  -h, -H, --help     See this help message\n  -V, --version      See NetMeter version"
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
# NetMeter Globals |
# ==================
class NetMeterGlobals:
    def __init__(self, args):
        self.pcapng_files_dir = args.data_dir + os.sep + "pcapng"
        self.csv_files_dir = args.data_dir + os.sep + "csv"
        # csv output dir is only created when needed
        self.csv_output_dir = self.csv_files_dir + os.sep + os.path.splitext(os.path.basename(args.pcap_path))[0]
        self.genes_dir = "network-objects" + os.sep + "genes"

# ============================
# START: Auxiliary Functions |
# ============================

# https://stackoverflow.com/questions/1392413/calculating-a-directorys-size-using-python
def get_dir_size(start_path):
    """Sum all file sizes inside directory, including subdirectories"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)

    return total_size

def get_size_str(size_bytes):
    """Format byte-size string"""
    size_str = (str(round(size_bytes/(1024**2), 3)) + " MBs (megabytes)") if (size_bytes < 1024**3) \
        else (str(round(size_bytes/(1024**3), 3)) + " GBs (gigabytes)")

    return size_str

def bitalker_id_to_pcap_filter(bitalker_id):
    """ Auxiliary function to convert a biflow id to a pcap filter. Right now, just used for debugging."""
    src_ip = bitalker_id[0]
    dst_ip = bitalker_id[1]

    src_ip_filter = "(" +\
        "(ip.addr==" + src_ip + ")" +\
        "&&" +\
        "(ip.addr==" + dst_ip + ")" +\
        ")"

    pcap_filter = src_ip_filter
    return pcap_filter

def biflow_id_to_pcap_filter(biflow_id):
    """ Auxiliary function to convert a biflow id to a pcap filter. Right now, just used for debugging."""
    src_ip = biflow_id[0]
    src_port_str = str(biflow_id[1])
    dst_ip = biflow_id[2]
    dst_port_str = str(biflow_id[3])
    l4_protocol = biflow_id[4]

    src_ip_filter = "(" +\
        "(ip.addr==" + src_ip + ")" +\
        "&&" +\
        "(ip.addr==" + dst_ip + ")" +\
        ")"

    src_port_filter = "(" +\
        "(" + l4_protocol.lower() + ".srcport==" + src_port_str + "&&" + l4_protocol.lower() + ".dstport==" + dst_port_str + ")" +\
        "||" +\
        "(" + l4_protocol.lower() + ".srcport==" + dst_port_str + "&&" + l4_protocol.lower() + ".dstport==" + src_port_str + ")" +\
        ")"
    pcap_filter = src_ip_filter + "&&" + src_port_filter
    return pcap_filter

def biflow_id_to_bitalker_id(biflow_id):
    """Get biflow_id's correspondent bitalker_id"""
    # Note: the researcher remodified the definition of bitalker to keep the BiFlow protocol_stack because then
    # it's possible to cluster most biflow genes while considering different protocols at this level
    bitalker_id = (biflow_id[0], biflow_id[2], biflow_id[4])
    return bitalker_id

def bitalker_id_to_unihost_id(bitalker_id, _reversed=False):
    """Get bitalker_id's correspondent unihost_id"""
    # Note: the researcher will keep the protocol_stack in this network object definition because we want to analyze
    # each protocol_stack independently (for now, at least)
    if not _reversed:
        unihost_id = (bitalker_id[0], bitalker_id[2])
    else:
        unihost_id = (bitalker_id[1], bitalker_id[2])

    return unihost_id

def iterator_to_str(iterator, separator="-"):
    """Convert biflow_id or bitalker_id iterables to string"""
    return separator.join(map(str,iterator))

def str_to_iterator(string, separator="-"):
    """Convert biflow_id or bitalker_id iterables to string"""
    return string.split(separator)

def datetime_to_unixtime(datetime_str):
    time_scale_factor = 1000.0
    datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
    datetime_format2 = "%Y-%m-%d %H:%M:%S"
    try:
        datetime_obj = datetime.datetime.strptime(datetime_str, datetime_format1)
    except ValueError:
        datetime_obj = datetime.datetime.strptime(datetime_str, datetime_format2)
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (datetime_obj - epoch).total_seconds() * time_scale_factor

def unixtime_to_datetime(ms_timestamp):
    time_scale_factor = 1000.0
    datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
    datetime_format2 = "%Y-%m-%d %H:%M:%S"
    try:
        datetime_obj = datetime.datetime.utcfromtimestamp(ms_timestamp/time_scale_factor).strftime(datetime_format1)
    except ValueError:
        datetime_obj = datetime.datetime.utcfromtimestamp(ms_timestamp/1000.0).strftime(datetime_format2)
    return datetime_obj

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ":".join("%02x" % compat_ord(b) for b in address)


def inet_to_str(inet):
    """
    Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def ipv4_dotted_to_int(ipv4_dotted):
    """Transforms an IP into its integer representation"""
    # FUTURE-TODO: handle IPv6
    ipv4_obj = ipaddress.IPv4Address(ipv4_dotted)
    ipv4_int = hex(int(ipv4_obj))[2:]
    return ipv4_int

def make_header_string(string, fwd_separator="#", bwd_separator="#", big_header_factor=1):
    """Transforms a string into an header"""
    fwd_separator_line = fwd_separator*len(string)
    bwd_separator_line = bwd_separator*len(string)

    header_string = Colors.BOLD + fwd_separator_line*big_header_factor + "\n" +\
        string + "\n" + bwd_separator_line*big_header_factor + Colors.ENDC
    return header_string

# ==========================
# END: Auxiliary Functions |
# ==========================



# ==========================================
# START: Generating PCAP Intel - Net Genes |
# ==========================================

def build_packets(input_file, args):
    """Process PCAP/PCAPNG file and build packets"""
    # Note: not using yielder due to outputting packet-level information 

    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("1.1. Packets"), flush=True)


    if input_file.name.endswith('.pcapng'):
        buffered_file_reader = dpkt.pcapng.Reader(input_file)
    elif input_file.name.endswith('.pcap'):
        buffered_file_reader = dpkt.pcap.Reader(input_file)
    else:
        print("File format '%s' is not recognized." %(input_file.name.split(".")[-1]))
        sys.exit(1)

    packet_no = 0
    n_packets_eth_ipv4_igmp = 0
    n_packets_eth_ipv4_icmp = 0
    n_packets_eth_ipv4_tcp = 0
    n_packets_eth_ipv4_udp = 0
    n_packets_eth_ipv4_others = 0
    n_packets_eth_ipv6 = 0
    n_packets_arp = 0
    n_packets_llc = 0
    n_packets_others = 0

    # TODO: https://dpkt.readthedocs.io/en/latest/print_icmp.html
    # TODO: find a database and dataset format which accomodates such diverse feature formats (tcp vs udp vs icmp) while maintaining
    # all the relevant genes for each format... maybe there needs to be dataset separation, or maybe it's enough to put a "L3-protocol"
    # and "L4-protocol" field to separate those formats in the same dataset and zero-out different values - it will complicate too much
    # when introducing mixed NetGenes (l3biflows/l4biflows/bitalkers/unihosts)
    packets = []
    
    # ===================
    # PARSE ALL PACKETS |
    # ===================
    # SHOULD-TODO: optimize this the best possible - no ideas for now except for using a listed yielder, but I lose nice verbose output
    # doing this, and it's not a significant performance
    for timestamp, buf in buffered_file_reader:
        # ================
        # LAYER1: ETHERNET
        # ================
        # FUTURE-TODO: implement handlers for other L1 protocols that dpkt doesn't support
        # buf contains the L1 data
        frame_len = len(buf)

        # ================
        # LAYER2: ETHERNET
        # ================
        # FUTURE-TODO: implement handlers for more L2 protocols

        # unpack the Ethernet frame (mac src, mac dst, ether type). Buf must be of the expected format: L1 Ethernet.
        eth = dpkt.ethernet.Ethernet(buf)
        packet_no += 1

        # check if frame is an EthL1-ARP packet
        if isinstance(eth.data, dpkt.arp.ARP):
            n_packets_arp += 1
            continue

        # check if frame is an EthL1-LLC packet
        if isinstance(eth.data, dpkt.llc.LLC):
            n_packets_llc += 1
            continue

        # ============
        # LAYER3: IPv4
        # ============
        # FUTURE-TODO: implement handlers for more L3 protocols

        # check if the Ethernet data contains an EthL1-EthL2-IPv6 packet
        if isinstance(eth.data, dpkt.ip6.IP6):
            n_packets_eth_ipv6 += 1
            continue

        # check if the Ethernet data contains an EthL1-EthL2-IPv4 packet. If it doesn't, ignore it.
        if not isinstance(eth.data, dpkt.ip.IP):
            n_packets_others += 1
            continue

        # unpack the data within the Ethernet frame: the confirmed EthL1-EthL2-IPv4 packet
        ipv4 = eth.data

        # -------------------------
        # IPv4-only packet genes
        # -------------------------
        #https://en.wikipedia.org/wiki/IPv4
        # Source and destination IP
        src_ip = inet_to_str(ipv4.src)
        dst_ip = inet_to_str(ipv4.dst)

        # IPv4 lengths
        ipv4_options_len = len(ipv4.opts)
        ipv4_header_len = ipv4.__hdr_len__ + ipv4_options_len
        ipv4_data_len = len(ipv4.data)

        # IPv4 Fragment information
        ipv4_df_flag = 1 if bool(ipv4.off & dpkt.ip.IP_DF) else 0
        ipv4_mf_flag = 1 if bool(ipv4.off & dpkt.ip.IP_MF) else 0

        # IPv4 Packet Genes
        ipv4_packet_genes = [str(datetime.datetime.utcfromtimestamp(timestamp)), ipv4_header_len, ipv4_data_len, ipv4_df_flag, ipv4_mf_flag]

        # ===========================================
        # LAYER3plus and LAYER4: Protocols above IPv4
        # ===========================================
        # FUTURE-TODO: implement handlers for more L3plus and L4 protocols

        # check if the Ethernet data contains an Eth-IPv4-ICMP packet
        if isinstance(ipv4.data, dpkt.icmp.ICMP):
            n_packets_eth_ipv4_icmp += 1
            continue
        # check if the Ethernet data contains an Eth-IPv4-IGMP packet
        elif isinstance(ipv4.data, dpkt.igmp.IGMP):
            n_packets_eth_ipv4_igmp += 1
            continue
        # check if the Ethernet data contains an Eth-IPv4-TCP packet
        elif isinstance(ipv4.data, dpkt.tcp.TCP):
            n_packets_eth_ipv4_tcp += 1
        # check if the Ethernet data contains an Eth-IPv4-UDP packet
        elif isinstance(ipv4.data, dpkt.udp.UDP):
            n_packets_eth_ipv4_udp += 1
        else:
            n_packets_eth_ipv4_others += 1
            continue

        # ===================
        # LAYER4: TCP and UDP
        # ===================
        # Note: TCP and UDP are the two most relevant protocols used for diverse attack vectors,
        # so the researcher focuses more on layer 4 (transport layer)

        # Unpack the data within the IPv4 frame: either TCP or UDP data
        l4_layer = ipv4.data

        # -----------------------
        # TCP/UDP packet genes
        # -----------------------
        # Extracting l4 protocol name
        l4_protocol_name = type(l4_layer).__name__

        # TCP/UDP source and destination ports
        src_port = l4_layer.sport
        dst_port = l4_layer.dport

        # TCP/UDP lengths
        l4_options_len = len(l4_layer.opts) if hasattr(l4_layer, "opts") else 0
        l4_header_len = l4_layer.__hdr_len__ + l4_options_len
        l4_data_len = len(l4_layer.data)
        l4_packet_genes = [l4_header_len, l4_data_len]

        # IPv4-L4 Flow Identifier: 6-tuple -> (src ip, src port, dst ip, dst port, protocol_stack, inner_sep_counter)
        # note: inner_sep_counter is incremented whenever a flow reaches its end, which is defined by the protocol used
        flow_id = [src_ip, src_port, dst_ip, dst_port, l4_protocol_name, 0]

        # Packet-level debug Info
        if args.debug == "1":
            print(make_header_string("Packet-level Debugging"), flush=True)
            print("[D] Packet no.:", packet_no, flush=True)
            print("[D] IPv4 header length:", ipv4_header_len, flush=True)
            print("[D] IPv4 options length:", ipv4_options_len, flush=True)
            print("[D] IPv4 data length:", ipv4_data_len, flush=True)
            print("[D] Transport header length:", l4_header_len, flush=True)
            print("[D] Transport options length:", l4_options_len, flush=True)
            print("[D] Transport data length:", l4_data_len, flush=True)

        packet_genes = [flow_id,] + ipv4_packet_genes + l4_packet_genes
        if l4_protocol_name == "TCP":
            # ===================
            # TCP packet genes
            # ===================
            # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
            # https://tools.ietf.org/html/rfc793

            tcp_fin_flag = ( l4_layer.flags & dpkt.tcp.TH_FIN ) != 0
            tcp_syn_flag = ( l4_layer.flags & dpkt.tcp.TH_SYN ) != 0
            tcp_rst_flag = ( l4_layer.flags & dpkt.tcp.TH_RST ) != 0
            tcp_psh_flag = ( l4_layer.flags & dpkt.tcp.TH_PUSH) != 0
            tcp_ack_flag = ( l4_layer.flags & dpkt.tcp.TH_ACK ) != 0
            tcp_urg_flag = ( l4_layer.flags & dpkt.tcp.TH_URG ) != 0
            tcp_ece_flag = ( l4_layer.flags & dpkt.tcp.TH_ECE ) != 0
            tcp_cwr_flag = ( l4_layer.flags & dpkt.tcp.TH_CWR ) != 0
            tcp_packet_genes = [tcp_fin_flag, tcp_syn_flag, tcp_rst_flag, tcp_psh_flag, tcp_ack_flag, tcp_urg_flag, tcp_ece_flag, tcp_cwr_flag]
            packet_genes += tcp_packet_genes
        elif l4_protocol_name == "UDP":
            # ================
            # UDP packet genes
            # ================
            # https://pdfs.semanticscholar.org/3648/75dcf14e886a9f9fa9310bb6fd9c8a4f4105.pdf
            # MAYBE-TODO: in case it applies, do udp packet genes
            udp_packet_genes = []
            packet_genes += udp_packet_genes
        # store packet genes
        packets.append(packet_genes)

    if args.verbose:
        print("[-] EthL1-ARP packets:" + Colors.RED, n_packets_arp, "packets" + Colors.ENDC, flush=True)
        print("[-] EthL1-LLC packets:" + Colors.RED, n_packets_llc, "packets" + Colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-ICMP packets:" + Colors.RED, n_packets_eth_ipv4_icmp, "packets" + Colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-IGMP packets:" + Colors.RED, n_packets_eth_ipv4_igmp, "packets" + Colors.ENDC, flush=True)
        print("[+] EthL1-EthL2-IPv4-TCP packets:" + Colors.GREEN, n_packets_eth_ipv4_tcp, "packets" + Colors.ENDC, flush=True)
        print("[+] EthL1-EthL2-IPv4-UDP packets:" + Colors.GREEN, n_packets_eth_ipv4_udp, "packets" + Colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-<Other L4> packets:" + Colors.RED, n_packets_eth_ipv4_others, "packets" + Colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv6 packets:" + Colors.RED, n_packets_eth_ipv6, "packets" + Colors.ENDC, flush=True)
        print("[-] <Other L1>, EthL1-<Other L2> and EthL1-EthL2-<Other L3> packets:" + Colors.RED, n_packets_others, "packets" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")
    
    # Verify some safe conditions
    if args.safe_check:
        if ipv4_header_len < 20 or ipv4_header_len > 60:
            print("[!] Invalid IPv4 header length in packet no.", packet_no, file=sys.stderr, flush=True)
            sys.exit(1)

    return packets

def build_l3_uniflows(packets):
    """Associate layer-3 uniflow ids to packets"""
    l3_uniflows = dict()
    l3_uniflow_ids = list()
    for packet in packets:
        flow_id = tuple(packet[0])
        try:
            l3_uniflows[flow_id].append(packet)
        except KeyError:
            l3_uniflow_ids.append(flow_id)
            l3_uniflows[flow_id] = [packet]

    return l3_uniflows, l3_uniflow_ids

def build_l3_biflows(l3_uniflows, l3_uniflow_ids):
    """Join unidirectional flow information into its bidirectional flow equivalent"""
    def get_unique_matching_l3_uniflow_ids(l3_uniflows, l3_uniflow_ids):
        """Local helper function to return matching unidirectional flow ids, with l3_fwd_flow_id
        as key and l3_bwd_flow_id as value, and not vice-versa"""
        matching_l3_uniflow_ids_dict = dict()
        l3_fwd_flow_ids = list()
        for l3_uniflow_id in l3_uniflow_ids:
            reversed_l3_uniflow_id = (l3_uniflow_id[2], l3_uniflow_id[3], l3_uniflow_id[0],
                l3_uniflow_id[1], l3_uniflow_id[4], l3_uniflow_id[5])

            # Note: O(n**2) --> O(n) optimization done using dictionary search
            if reversed_l3_uniflow_id in l3_uniflows:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = reversed_l3_uniflow_id
            else:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = False
        return matching_l3_uniflow_ids_dict, l3_fwd_flow_ids

    matching_l3_uniflow_ids_dict, l3_fwd_flow_ids = get_unique_matching_l3_uniflow_ids(l3_uniflows, l3_uniflow_ids)
    l3_biflows = dict()
    l3_biflow_ids = list()

    for l3_fwd_flow_id in l3_fwd_flow_ids:
        # have in mind every l3_uniflow_id in this list will have been constituted by the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet, hence the researcher defines l3_biflow_id = l3_fwd_flow_id
        l3_bwd_flow_id = matching_l3_uniflow_ids_dict[l3_fwd_flow_id]
        l3_biflow_ids.append(l3_fwd_flow_id)
        if l3_bwd_flow_id:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id] + l3_uniflows[l3_bwd_flow_id]
        else:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id]
    return l3_biflows, l3_biflow_ids

class RFC793:
    def __init__(self):
        # INITIATION STATES
        self.flow_initiated = False
        self.flow_initiation_r1 = False
        self.flow_initiation_r2 = False
        self.flow_initiation_r3 = False

        # TERMINATION STATES
        self.flow_terminated = False
        self.flow_termination_r1 = False
        self.flow_termination_r2 = False
        self.flow_termination_r3 = False

        # CONCEPTUAL FEATURES
        self.biflow_eth_ipv4_tcp_initiation_two_way_handshake = False
        self.biflow_eth_ipv4_tcp_full_duplex_connection_established = False
        self.biflow_eth_ipv4_tcp_half_duplex_connection_established = False
        self.biflow_eth_ipv4_tcp_connection_rejected = False
        self.biflow_eth_ipv4_tcp_connection_dropped = False
        self.biflow_eth_ipv4_tcp_termination_graceful = False
        self.biflow_eth_ipv4_tcp_termination_abort = False
        self.biflow_eth_ipv4_tcp_termination_null = False

    def reset_states_and_genes(self):
        # if the flow hasn't terminated, won't reset states and genes
        if not self.flow_terminated:
            return

        # INITIATION STATES
        self.flow_initiated = False
        self.flow_initiation_r1 = False
        self.flow_initiation_r2 = False
        self.flow_initiation_r3 = False

        # TERMINATION STATES
        self.flow_terminated = False
        self.flow_termination_r1 = False
        self.flow_termination_r2 = False
        self.flow_termination_r3 = False

        # CONCEPTUAL FEATURES
        self.biflow_eth_ipv4_tcp_initiation_two_way_handshake = False
        self.biflow_eth_ipv4_tcp_full_duplex_connection_established = False
        self.biflow_eth_ipv4_tcp_half_duplex_connection_established = False
        self.biflow_eth_ipv4_tcp_connection_rejected = False
        self.biflow_eth_ipv4_tcp_connection_dropped = False
        self.biflow_eth_ipv4_tcp_termination_graceful = False
        self.biflow_eth_ipv4_tcp_termination_abort = False
        self.biflow_eth_ipv4_tcp_termination_null = False

    def get_rfc793_tcp_biflow_conceptual_features(self):
        rfc793_tcp_biflow_conceptual_features = [
            self.biflow_eth_ipv4_tcp_initiation_two_way_handshake,
            self.biflow_eth_ipv4_tcp_full_duplex_connection_established,
            self.biflow_eth_ipv4_tcp_half_duplex_connection_established,
            self.biflow_eth_ipv4_tcp_connection_rejected,
            self.biflow_eth_ipv4_tcp_connection_dropped,
            self.biflow_eth_ipv4_tcp_termination_graceful,
            self.biflow_eth_ipv4_tcp_termination_abort,
            self.biflow_eth_ipv4_tcp_termination_null
        ]

        return rfc793_tcp_biflow_conceptual_features



def build_l4_biflows(l3_biflows, l3_biflow_ids, args):
    """Separate layer-3 bidirectional flows by layer-4 protocol and
    build layer-4 bidirectional flows according to TCP and UDP RFCs"""
    def build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, args):
        """Local helper function to build TCP BiFlows according to RFC793"""
        def set_inner_sep_counter(packet_list, inner_sep_counter):
            """Local helper function to update flows' packets to the right inner_sep_counter,
            thus correcting its flow_id"""
            for i, packet in enumerate(packet_list):
                # set each packet's inner_sep_counter
                packet_list[i][0][5] = inner_sep_counter
            
            return packet_list
        # COULD-TODO: validate using tcp_seq
        rfc793_tcp_biflow_conceptual_features = dict()
        rfc793_tcp_biflows = dict()
        rfc793_tcp_biflow_ids = []
        n_disconected_rfc793_packets = 0

        # create RFC793-compliant TCP flows
        for tmp_tcp_biflow_id in tmp_tcp_biflow_ids:
            curr_flow = tmp_tcp_biflows[tmp_tcp_biflow_id]
            # sorting the packets in each flow by timestamp
            curr_flow.sort(key=lambda x: x[1])
            flow_any_n_packets = len(curr_flow)

            if flow_any_n_packets == 0:
                print("[!] A flow can't have 0 packets.", file=sys.stderr, flush=True)
                sys.exit(1)
            else:
                # =================================
                # RFC793-compliant TCP BiFlow Genes
                # =================================
                rfc793 = RFC793()
                rfc793_tcp_biflow_id = None

                # ==============
                # RFC793 parsing
                # ==============
                curr_packet_index = 0
                previous_packet_index = 0
                inner_sep_counter = 0

                while curr_packet_index < flow_any_n_packets:
                    # ===================
                    # Gathering TCP flags
                    # ===================
                    fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1 = curr_flow[curr_packet_index][-8:]
                    try:
                        fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = curr_flow[curr_packet_index+1][-8:]
                    except IndexError:
                        fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = [False]*8
                    try:
                        fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3 = curr_flow[curr_packet_index+2][-8:]
                    except IndexError:
                        fin3,syn3,rst3,psh3,ack3,urg2,ece3,cwr3 = [False]*8
                    
                    # =========================
                    # TCP FLOW INITIATION RULES
                    # =========================
                    # Begin Flow: tcp_three_way_handshake (r1), tcp_two_way_handshake (r2) and connection request (r3)
                    # 3-way handshake (full-duplex): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack)
                    rfc793.flow_initiation_r1 = (syn1 and not ack1) and (syn2 and ack2) and ack3
                    # 2-way handshake (half-duplex): (syn,ack) or (syn,syn-ack)
                    rfc793.flow_initiation_r2 = (syn1 and not ack1) and ack2
                    # Connection request: (syn)
                    rfc793.flow_initiation_r3 = (syn1 and not ack1)

                    # ==========================
                    # TCP FLOW TERMINATION RULES
                    # ==========================
                    # End Flow: tcp_graceful_termination (r1), tcp_abort_termination (r2) and last packet (r3)
                    # graceful termination
                    rfc793.flow_termination_r1 = fin1 and (fin2 and ack2) and ack3
                    # abort termination
                    rfc793.flow_termination_r2 = rst1 and not rst2
                    # null termination
                    rfc793.flow_termination_r3 = (curr_packet_index == flow_any_n_packets-1)

                    if not rfc793.flow_initiated:
                        # ===================
                        # TCP FLOW INITIATION
                        # ===================
                        # Note 1: Consider flow begin or ignore it (considering it is safer, but not considering it will
                        # leave out flows that have started before the capture)
                        # Note 2: We consider flows only the ones that start with a 2 or 3-way handshake (r1,r2). In case
                        # there's no second acknowledgement, the connection was dropped and, nonetheless, the researcher
                        # considers it a flow
                        # -------------------
                        # Three-way Handshake
                        # -------------------
                        if rfc793.flow_initiation_r1:
                            # Note: Any three-way handshake initiates a full-duplex connection, no need to duplicate variables
                            rfc793.flow_initiated = True
                            # ----------------------------------
                            # Established Full-Duplex Connection
                            # ----------------------------------
                            rfc793.biflow_eth_ipv4_tcp_full_duplex_connection_established = True
                        # -----------------
                        # Two-way Handshake
                        # -----------------
                        elif rfc793.flow_initiation_r2:
                            # Note: Rare occurrence, except in the case of rejected and dropped connections:
                            # 1. After receiving syn, the receiving endpoint acknowledges the connection request and aborts it.
                            # The connection is acknowledged (ack) and immediately terminated (rst) in the same packet: REJECT.
                            # The most common 2nd packet flags are (rst-ack), ack used for the connection acknowledgement (two-way handshake)
                            # and reset used for immediately rejecting the connection
                            # 2. After receiving syn, the receiving endpoint acknowledges the connection request and accepts it.
                            # The connection is acknowledged (syn-ack) but never initiated: (syn, syn-ack). It might or not be
                            # terminated afterwards, since it is very common that it's a portscan and a reset is received right
                            # afterwards or, in more uncommon cases where an attacker can close a TCP connection and not send a
                            # RST packet, no message is received at all by the endpoint, but these termination cases are handled
                            # by our flow termination rules later.
                            rfc793.flow_initiated = True
                            rfc793.biflow_eth_ipv4_tcp_initiation_two_way_handshake = True

                            # -------------------
                            # Rejected Connection
                            # -------------------
                            if rst2:
                                rfc793.biflow_eth_ipv4_tcp_connection_rejected = True
                            # ----------------------------------
                            # Established Half-Duplex Connection
                            # ----------------------------------
                            else:
                                rfc793.biflow_eth_ipv4_tcp_half_duplex_connection_established = True
                        # ---------------------------------
                        # Unacknowledged Connection Request
                        # ---------------------------------
                        elif rfc793.flow_initiation_r3:
                            # 1. After receiving syn, the receiving endpoint ignores the connection request and drops it: DROP.
                            rfc793.flow_initiated = True
                            # ------------------
                            # Dropped connection
                            # ------------------
                            rfc793.biflow_eth_ipv4_tcp_connection_dropped = True

                    # the flow end conditions are r1 and r2, (fin,fin-ack,ack)/(rst,!rst,---),
                    # or if the packet is the last one of the existing communication
                    # SHOULD-TODO: Improve this spaghetti hardcoded code
                    if rfc793.flow_initiated:
                        rfc793_tcp_biflow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                            tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + inner_sep_counter)
                        next_packet_index = 0
                        # ====================
                        # TCP FLOW TERMINATION
                        # ====================
                        # graceful termination
                        if rfc793.flow_termination_r1:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_graceful = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+3]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 3
                            inner_sep_counter += 1
                        # abort termination
                        elif rfc793.flow_termination_r2:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_abort = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+1]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                        # null termination
                        elif rfc793.flow_termination_r3:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_null = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+1]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                    elif not rfc793_tcp_biflow_id:
                        # disconected packet
                        n_disconected_rfc793_packets += 1
                    else:
                        # just packets
                        pass

                    # =====================
                    # TCP BiFlow Debug Info
                    # =====================
                    if args.debug == "2":
                        # Initiation/Connection Types
                        if rfc793.biflow_eth_ipv4_tcp_full_duplex_connection_established:
                            print("[D] IPv4-TCP Full-Duplex Connection Established (3-way Handshake): " +\
                                biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_half_duplex_connection_established:
                            print("[D] IPv4-TCP Half-Duplex Connection Established (2-way Handshake): " +\
                                biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_connection_rejected:
                            print("[D] IPv4-TCP Rejected Connection (2-way Handshake): " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_connection_dropped:
                            print("[D] IPv4-TCP Dropped Connection (No Handshake): " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)

                        # Termination Types
                        if rfc793.biflow_eth_ipv4_tcp_termination_graceful:
                            print("[D] IPv4-TCP Graceful Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_termination_abort:
                            print("[D] IPv4-TCP Abort Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_termination_null:
                            print("[D] IPv4-TCP Null Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)

                    # =====================================================================================================
                    # Flow Termination: reset all inside loop, in case there's a 6-tuple biflow inside this 5-tuple parsing
                    # =====================================================================================================
                    rfc793.reset_states_and_genes()

                    # keep iterating through the packets
                    curr_packet_index += 1

        return rfc793_tcp_biflows, rfc793_tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets

    # ==================================
    # Separate L3 BiFlows by L4 protocol
    # ==================================
    udp_biflows, udp_biflow_ids = dict(), list()
    tmp_tcp_biflows, tmp_tcp_biflow_ids = dict(), list()
    for l3_biflow_id in l3_biflow_ids:
        biflow = l3_biflows[l3_biflow_id]
        l4_protocol_name = l3_biflow_id[4]
        if l4_protocol_name == "UDP":
            udp_biflows[l3_biflow_id] = biflow
            udp_biflow_ids.append(l3_biflow_id)
        elif l4_protocol_name == "TCP":
            tmp_tcp_biflows[l3_biflow_id] = biflow
            tmp_tcp_biflow_ids.append(l3_biflow_id)
        else:
            print("ERROR: Run-time should never reach this branch, but in case it does, it means that another protocol was let through in an earlier stage.",
                file=sys.stderr, flush=True)
            sys.exit(1)

    # Apply RFC793 to the unseparated TCP BiFlows
    tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets = build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, args)
    #tcp_biflows, tcp_biflow_ids = tmp_tcp_biflows, tmp_tcp_biflow_ids
    return udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets

def check_supported_network_objects(network_object_type):
    """ Check if network object type is supported"""
    if network_object_type not in ("biflow", "bitalker", "unihost"):
        print("[!] Network object type \"" + network_object_type + "\" not supported. Supported protocol stacks: biflow, bitalker, unihost",\
            file=sys.stderr, flush=True)
        sys.exit(1)

def check_supported_protocol_stacks(protocol_stack):
    """ Check if protocol stack is supported"""
    if protocol_stack not in ("ipv4", "ipv4-l4", "ipv4-tcp"):
        print("[!] Protocol stack \"" + protocol_stack + "\" not supported. Supported protocol stacks: ipv4, ipv4-l4, ipv4-tcp",\
            file=sys.stderr, flush=True)
        sys.exit(1)

def get_network_object_header(network_object_type, protocol_stack):
    """Use L3-L4 protocol stack to fetch correct biflow headers and return them as a list"""

    # Check network object type
    check_supported_network_objects(network_object_type)
    # Check protocol stack
    check_supported_protocol_stacks(protocol_stack)

    # Get NetGenes header in the form of a list
    net_genes_filepath = netmeter_globals.genes_dir + os.sep + "%s-%s-header.txt"%(network_object_type, protocol_stack)
    f = open(net_genes_filepath, "r")
    net_genes_header_lst = f.read().split("\n")
    f.close()

    return net_genes_header_lst

def get_l3_l4_biflow_gene_generators(ipv4_udp_biflows, ipv4_udp_biflow_ids, ipv4_tcp_biflows, ipv4_tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features):
    """Return L3-L4 biflow gene generators"""
    def calculate_l3_l4_biflow_genes(biflows, biflow_ids, l4_protocol=None, l4_conceptual_features=None):
        """Calculate and yield L3-L4 biflow genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_biflow_genes_header_list = get_network_object_header("biflow", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_biflow_genes_header_list = get_network_object_header("biflow", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_biflow_genes_header_list = get_network_object_header("biflow", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_biflow_genes_header_list = ipv4_biflow_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_biflow_genes_header_list += ipv4_l4_biflow_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_biflow_genes_header_list += ipv4_tcp_biflow_genes_header_list

        for biflow_id in biflow_ids:
            # DEV-NOTE: curr_biflow[packet_index][packet_gene_index]
            # NOTE: backward packets may not exist
            curr_biflow = biflows[biflow_id]
            if l4_conceptual_features:
                curr_biflow_l4_conceptual_features = l4_conceptual_features[biflow_id]
                # ====================================
                # Set Local L4 Conceptual Feature Vars
                # ====================================
                # TCP
                if l4_protocol == "TCP":
                    biflow_eth_ipv4_tcp_initiation_two_way_handshake = curr_biflow_l4_conceptual_features[0]
                    biflow_eth_ipv4_tcp_full_duplex_connection_established = curr_biflow_l4_conceptual_features[1]
                    biflow_eth_ipv4_tcp_half_duplex_connection_established = curr_biflow_l4_conceptual_features[2]
                    biflow_eth_ipv4_tcp_connection_rejected = curr_biflow_l4_conceptual_features[3]
                    biflow_eth_ipv4_tcp_connection_dropped = curr_biflow_l4_conceptual_features[4]
                    biflow_eth_ipv4_tcp_termination_graceful = curr_biflow_l4_conceptual_features[5]
                    biflow_eth_ipv4_tcp_termination_abort = curr_biflow_l4_conceptual_features[6]
                    biflow_eth_ipv4_tcp_termination_null = curr_biflow_l4_conceptual_features[7]

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ======
            # Packet
            # ======
            # ----------------
            # Packet Frequency
            # ----------------
            biflow_any_n_packets = len(curr_biflow)
            biflow_fwd_n_packets = 0
            biflow_bwd_n_packets = 0

            # ================================
            # Packet & Byte Frequency Features
            # ================================
            # done below

            # -------------------
            # Inter-arrival Times
            # -------------------
            biflow_any_iats = list()
            biflow_fwd_iats = list()
            biflow_bwd_iats = list()

            # ====
            # IPv4
            # ====
            # -------------------
            # IPv4 Header Lengths
            # -------------------
            biflow_any_eth_ipv4_data_lens = list()
            biflow_fwd_eth_ipv4_data_lens = list()
            biflow_bwd_eth_ipv4_data_lens = list()

            # -----------------
            # IPv4 Data Lengths
            # -----------------
            biflow_any_eth_ipv4_header_lens = list()
            biflow_fwd_eth_ipv4_header_lens = list()
            biflow_bwd_eth_ipv4_header_lens = list()

            # ------------------------
            # IPv4 Fragmentation Flags
            # ------------------------
            biflow_any_eth_ip_df_flags = list()
            biflow_fwd_eth_ip_df_flags = list()
            biflow_bwd_eth_ip_df_flags = list()

            biflow_any_eth_ip_mf_flags = list()
            biflow_fwd_eth_ip_mf_flags = list()
            biflow_bwd_eth_ip_mf_flags = list()

            # ==
            # L4
            # ==
            # ------------------------
            # L4 Data Packet Frequency
            # ------------------------
            biflow_any_eth_ipv4_l4_n_data_packets = 0
            biflow_fwd_eth_ipv4_l4_n_data_packets = 0
            biflow_bwd_eth_ipv4_l4_n_data_packets = 0

            # -----------------
            # L4 Header Lengths
            # -----------------
            biflow_any_eth_ipv4_l4_header_lens = list()
            biflow_fwd_eth_ipv4_l4_header_lens = list()
            biflow_bwd_eth_ipv4_l4_header_lens = list()

            # ---------------
            # L4 Data Lengths
            # ---------------
            biflow_any_eth_ipv4_l4_data_lens = list()
            biflow_fwd_eth_ipv4_l4_data_lens = list()
            biflow_bwd_eth_ipv4_l4_data_lens = list()

            # ===
            # TCP
            # ===
            # --------------
            # TCP Flow Flags
            # --------------
            biflow_any_eth_ipv4_tcp_fin_flags = list()
            biflow_any_eth_ipv4_tcp_syn_flags = list()
            biflow_any_eth_ipv4_tcp_rst_flags = list()
            biflow_any_eth_ipv4_tcp_psh_flags = list()
            biflow_any_eth_ipv4_tcp_ack_flags = list()
            biflow_any_eth_ipv4_tcp_urg_flags = list()
            biflow_any_eth_ipv4_tcp_ece_flags = list()
            biflow_any_eth_ipv4_tcp_cwr_flags = list()

            biflow_fwd_eth_ipv4_tcp_fin_flags = list()
            biflow_fwd_eth_ipv4_tcp_syn_flags = list()
            biflow_fwd_eth_ipv4_tcp_rst_flags = list()
            biflow_fwd_eth_ipv4_tcp_psh_flags = list()
            biflow_fwd_eth_ipv4_tcp_ack_flags = list()
            biflow_fwd_eth_ipv4_tcp_urg_flags = list()
            biflow_fwd_eth_ipv4_tcp_ece_flags = list()
            biflow_fwd_eth_ipv4_tcp_cwr_flags = list()

            biflow_bwd_eth_ipv4_tcp_fin_flags = list()
            biflow_bwd_eth_ipv4_tcp_syn_flags = list()
            biflow_bwd_eth_ipv4_tcp_rst_flags = list()
            biflow_bwd_eth_ipv4_tcp_psh_flags = list()
            biflow_bwd_eth_ipv4_tcp_ack_flags = list()
            biflow_bwd_eth_ipv4_tcp_urg_flags = list()
            biflow_bwd_eth_ipv4_tcp_ece_flags = list()
            biflow_bwd_eth_ipv4_tcp_cwr_flags = list()

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_packet_index = 0
            while curr_packet_index < biflow_any_n_packets:
                # ===============
                # Packet Concepts
                # ===============
                if curr_packet_index >= 1:
                    previous_packet = curr_biflow[curr_packet_index-1]
                    previous_packet_biflow_id = tuple(previous_packet[0])
                    previous_packet_timestamp = previous_packet[1]

                curr_packet = curr_biflow[curr_packet_index]
                curr_packet_biflow_id = tuple(curr_packet[0])
                curr_packet_timestamp = curr_packet[1]
                curr_packet_eth_ipv4_header_len = curr_packet[2]
                curr_packet_eth_ipv4_data_len = curr_packet[3]
                curr_packet_eth_ip_df_flag = curr_packet[4]
                curr_packet_eth_ip_mf_flag = curr_packet[5]

                # Packet IAT requires that there's at least two packets
                if curr_packet_index >= 1:
                    previous_packet_time = datetime_to_unixtime(previous_packet_timestamp)
                    curr_packet_time = datetime_to_unixtime(curr_packet_timestamp)
                    curr_packet_iat = (curr_packet_time - previous_packet_time)/time_scale_factor
                    biflow_any_iats.append(curr_packet_iat)
                    if previous_packet_biflow_id == biflow_id:
                        biflow_fwd_iats.append(curr_packet_iat)
                    else:
                        biflow_bwd_iats.append(curr_packet_iat)

                # =============
                # IPv4 Concepts
                # =============
                # STATISTICAL
                biflow_any_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                biflow_any_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                biflow_any_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                biflow_any_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)

                if curr_packet_biflow_id == biflow_id:
                    # CONCEPTUAL
                    biflow_fwd_n_packets += 1

                    # STATISTICAL
                    biflow_fwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                    biflow_fwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                    biflow_fwd_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                    biflow_fwd_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)
                else:
                    # CONCEPTUAL
                    biflow_bwd_n_packets += 1

                    # STATISTICAL
                    biflow_bwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                    biflow_bwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                    biflow_bwd_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                    biflow_bwd_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    curr_packet_eth_ipv4_l4_header_len = curr_packet[6]
                    curr_packet_eth_ipv4_l4_data_len = curr_packet[7]

                    # any
                    biflow_any_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                    biflow_any_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)

                    #fwd
                    if curr_packet_biflow_id == biflow_id:
                        # CONCEPTUAL
                        if curr_packet_eth_ipv4_l4_data_len > 0:
                            biflow_any_eth_ipv4_l4_n_data_packets += 1
                            biflow_fwd_eth_ipv4_l4_n_data_packets += 1

                        # STATISTICAL
                        biflow_fwd_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                        biflow_fwd_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)
                    #bwd
                    else:
                        # CONCEPTUAL
                        if curr_packet_eth_ipv4_l4_data_len > 0:
                            biflow_any_eth_ipv4_l4_n_data_packets += 1
                            biflow_bwd_eth_ipv4_l4_n_data_packets += 1

                        # STATISTICAL
                        biflow_bwd_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                        biflow_bwd_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        curr_packet_eth_ipv4_tcp_fin_flag = curr_packet[-8]
                        curr_packet_eth_ipv4_tcp_syn_flag = curr_packet[-7]
                        curr_packet_eth_ipv4_tcp_rst_flag = curr_packet[-6]
                        curr_packet_eth_ipv4_tcp_psh_flag = curr_packet[-5]
                        curr_packet_eth_ipv4_tcp_ack_flag = curr_packet[-4]
                        curr_packet_eth_ipv4_tcp_urg_flag = curr_packet[-3]
                        curr_packet_eth_ipv4_tcp_ece_flag = curr_packet[-2]
                        curr_packet_eth_ipv4_tcp_cwr_flag = curr_packet[-1]

                        # any
                        biflow_any_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                        biflow_any_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                        biflow_any_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                        biflow_any_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                        biflow_any_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                        biflow_any_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                        biflow_any_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                        biflow_any_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)

                        #fwd
                        if curr_packet_biflow_id == biflow_id:
                            biflow_fwd_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                            biflow_fwd_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                            biflow_fwd_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                            biflow_fwd_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                            biflow_fwd_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                            biflow_fwd_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                            biflow_fwd_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                            biflow_fwd_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)
                        #bwd
                        else:
                            biflow_bwd_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                            biflow_bwd_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                            biflow_bwd_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                            biflow_bwd_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                            biflow_bwd_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                            biflow_bwd_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                            biflow_bwd_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                            biflow_bwd_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)
                # keep iterating through the packets
                curr_packet_index+=1

            # TCP BiFlow direction
            if biflow_fwd_n_packets == 0:
                # -------------------------------------------------------------------
                # Note 1: In case this is reached, TCP BiFlow direction got messed up
                # This sometimes happens for an unknown reason in datasets.
                # The researcher speculates it might have something to do with
                # the dataset creators having merged small pcap files from different
                # endpoints or the fact that the network interface itself registered
                # the two packets in a different order relatively to their respective
                # sending and receival times.
                # An example of this is the Thursday-WorkingHours file of the CICIDS-2017
                # dataset, in the afternoon, when a Windows Vista endpoint (192.168.10.8)
                # performs a portscan on all other network clients. The eBPF filter for the
                # bitalker is '((ip.addr==192.168.10.8)&&(ip.addr==192.168.10.9))', and
                # for the specific biflow where this happens is
                # '((ip.addr==192.168.10.8)&&(ip.addr==192.168.10.9))&&((tcp.srcport==45500&&tcp.dstport==407)||(tcp.srcport==407&&tcp.dstport==45500))'
                # --------------------------------------------------------------------------------------------------------------------------------------
                # Note 2: in case this happens, we will ignore this biflow by continuing to process other biflows.
                # SHOULD-TODO: Despite this, we are ignoring the 6-tuple biflow when we should be ignoring the whole
                # 5-tuple biflow instead. I don't currently know how to implement this effectively in the current code
                # and, thus, will ignore it for now because there aren't many biflows that encounter this "mistiming"
                # (only found it in the Thursday capture, for portscans)
                if args.verbose:
                    print(Colors.RED + iterator_to_str(biflow_id), "is an out-of-order BiFlow. Ignoring..." + Colors.ENDC)
                continue

            # ================================
            # ENRICH AND EXTRACT INFORMATION |
            # ================================

            # ======================
            # ADDITIONAL INFORMATION
            # ======================
            # Get bitalker_id and convert bitalker_id and biflow_id to strings
            bitalker_id = iterator_to_str(biflow_id_to_bitalker_id(biflow_id))
            biflow_id = iterator_to_str(biflow_id)

            first_packet = curr_biflow[0]
            last_packet = curr_biflow[-1]
            first_packet_timestamp = first_packet[1]
            last_packet_timestamp = last_packet[1]
            biflow_any_first_packet_time = datetime_to_unixtime(first_packet_timestamp)
            biflow_any_last_packet_time = datetime_to_unixtime(last_packet_timestamp)

            # =================
            # IPv4 Data Lengths
            # =================
            biflow_any_eth_ipv4_data_len_total = round(sum(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_mean = round(np.mean(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_std = round(np.std(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_var = round(np.var(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_max = round(max(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_min = round(min(biflow_any_eth_ipv4_data_lens), 3)

            biflow_fwd_eth_ipv4_data_len_total = round(sum(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_mean = round(np.mean(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_std = round(np.std(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_var = round(np.var(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_max = round(max(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_min = round(min(biflow_fwd_eth_ipv4_data_lens), 3)

            if len(biflow_bwd_eth_ipv4_data_lens) == 0:
                biflow_bwd_eth_ipv4_data_len_total = biflow_bwd_eth_ipv4_data_len_max = biflow_bwd_eth_ipv4_data_len_min = 0
                biflow_bwd_eth_ipv4_data_len_mean = biflow_bwd_eth_ipv4_data_len_std = biflow_bwd_eth_ipv4_data_len_var = 0.0
            else:
                biflow_bwd_eth_ipv4_data_len_total = round(sum(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_mean = round(np.mean(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_std = round(np.std(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_var = round(np.var(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_max = round(max(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_min = round(min(biflow_bwd_eth_ipv4_data_lens), 3)

            # =============
            # Time Features
            # =============
            biflow_any_duration = round((biflow_any_last_packet_time - biflow_any_first_packet_time)/time_scale_factor, 3)

            # =================================
            # Additional Information - Reformat
            # =================================
            biflow_any_first_packet_time = unixtime_to_datetime(biflow_any_first_packet_time)
            biflow_any_last_packet_time = unixtime_to_datetime(biflow_any_last_packet_time)

            # ================================
            # Packet & Byte Frequency Features
            # ================================
            if biflow_any_duration == 0:
                biflow_any_packets_per_sec = biflow_fwd_packets_per_sec = biflow_bwd_packets_per_sec = 0.0
                biflow_any_bytes_per_sec = biflow_fwd_bytes_per_sec = biflow_bwd_bytes_per_sec = 0.0
            else:
                biflow_any_packets_per_sec = round(biflow_any_n_packets/biflow_any_duration, 3)
                biflow_fwd_packets_per_sec = round(biflow_fwd_n_packets/biflow_any_duration, 3)
                biflow_bwd_packets_per_sec = round(biflow_bwd_n_packets/biflow_any_duration, 3)
                biflow_any_bytes_per_sec = round(biflow_any_eth_ipv4_data_len_total/biflow_any_duration, 3)
                biflow_fwd_bytes_per_sec = round(biflow_fwd_eth_ipv4_data_len_total/biflow_any_duration, 3)
                biflow_bwd_bytes_per_sec = round(biflow_bwd_eth_ipv4_data_len_total/biflow_any_duration, 3)

            # ===================
            # IPv4 Header Lengths
            # ===================
            biflow_any_eth_ipv4_header_len_total = round(sum(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_mean = round(np.mean(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_std = round(np.std(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_var = round(np.var(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_max = round(max(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_min = round(min(biflow_any_eth_ipv4_header_lens), 3)

            biflow_fwd_eth_ipv4_header_len_total = round(sum(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_mean = round(np.mean(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_std = round(np.std(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_var = round(np.var(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_max = round(max(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_min = round(min(biflow_fwd_eth_ipv4_header_lens), 3)

            if len(biflow_bwd_eth_ipv4_header_lens) == 0:
                biflow_bwd_eth_ipv4_header_len_total = biflow_bwd_eth_ipv4_header_len_max = biflow_bwd_eth_ipv4_header_len_min = 0
                biflow_bwd_eth_ipv4_header_len_mean = biflow_bwd_eth_ipv4_header_len_std = biflow_bwd_eth_ipv4_header_len_var = 0.0
            else:
                biflow_bwd_eth_ipv4_header_len_total = round(sum(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_mean = round(np.mean(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_std = round(np.std(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_var = round(np.var(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_max = round(max(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_min = round(min(biflow_bwd_eth_ipv4_header_lens), 3)
                

            # ==========================
            # Packet Inter-arrival Times
            # ==========================
            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_any_iats) == 0:
                biflow_any_iat_total = biflow_any_iat_max = biflow_any_iat_min = 0.0
                biflow_any_iat_mean = biflow_any_iat_std = biflow_any_iat_var = 0.0
            else:
                biflow_any_iat_total = round(sum(biflow_any_iats), 3)
                biflow_any_iat_mean = round(np.mean(biflow_any_iats), 3)
                biflow_any_iat_std = round(np.std(biflow_any_iats), 3)
                biflow_any_iat_var = round(np.var(biflow_any_iats), 3)
                biflow_any_iat_max = round(max(biflow_any_iats), 3)
                biflow_any_iat_min = round(min(biflow_any_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_fwd_iats) == 0:
                biflow_fwd_iat_total = biflow_fwd_iat_max = biflow_fwd_iat_min = 0.0
                biflow_fwd_iat_mean = biflow_fwd_iat_std = biflow_fwd_iat_var = 0.0
            else:
                biflow_fwd_iat_total = round(sum(biflow_fwd_iats), 3)
                biflow_fwd_iat_mean = round(np.mean(biflow_fwd_iats), 3)
                biflow_fwd_iat_std = round(np.std(biflow_fwd_iats), 3)
                biflow_fwd_iat_var = round(np.var(biflow_fwd_iats), 3)
                biflow_fwd_iat_max = round(max(biflow_fwd_iats), 3)
                biflow_fwd_iat_min = round(min(biflow_fwd_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_bwd_iats) == 0:
                biflow_bwd_iat_total = biflow_bwd_iat_max = biflow_bwd_iat_min = 0.0
                biflow_bwd_iat_mean = biflow_bwd_iat_std = biflow_bwd_iat_var = 0.0
            else:
                biflow_bwd_iat_total = round(sum(biflow_bwd_iats), 3)
                biflow_bwd_iat_mean = round(np.mean(biflow_bwd_iats), 3)
                biflow_bwd_iat_std = round(np.std(biflow_bwd_iats), 3)
                biflow_bwd_iat_var = round(np.var(biflow_bwd_iats), 3)
                biflow_bwd_iat_max = round(max(biflow_bwd_iats), 3)
                biflow_bwd_iat_min = round(min(biflow_bwd_iats), 3)

            # ======================
            # IP Fragmentation Flags
            # ======================
            biflow_any_eth_ip_df_flags_total = round(sum(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_mean = round(np.mean(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_std = round(np.std(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_var = round(np.var(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_max = round(max(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_min = round(min(biflow_any_eth_ip_df_flags), 3)

            biflow_fwd_eth_ip_df_flags_total = round(sum(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_mean = round(np.mean(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_std = round(np.std(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_var = round(np.var(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_max = round(max(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_min = round(min(biflow_fwd_eth_ip_df_flags), 3)

            if len(biflow_bwd_eth_ip_df_flags) == 0:
                biflow_bwd_eth_ip_df_flags_total = biflow_bwd_eth_ip_df_flags_max = biflow_bwd_eth_ip_df_flags_min = 0
                biflow_bwd_eth_ip_df_flags_mean = biflow_bwd_eth_ip_df_flags_std = biflow_bwd_eth_ip_df_flags_var = 0.0
            else:
                biflow_bwd_eth_ip_df_flags_total = round(sum(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_mean = round(np.mean(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_std = round(np.std(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_var = round(np.var(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_max = round(max(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_min = round(min(biflow_bwd_eth_ip_df_flags), 3)

            biflow_any_eth_ip_mf_flags_total = round(sum(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_mean = round(np.mean(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_std = round(np.std(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_var = round(np.var(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_max = round(max(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_min = round(min(biflow_any_eth_ip_mf_flags), 3)

            biflow_fwd_eth_ip_mf_flags_total = round(sum(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_mean = round(np.mean(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_std = round(np.std(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_var = round(np.var(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_max = round(max(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_min = round(min(biflow_fwd_eth_ip_mf_flags), 3)

            if len(biflow_bwd_eth_ip_mf_flags) == 0:
                biflow_bwd_eth_ip_mf_flags_total = biflow_bwd_eth_ip_mf_flags_max = biflow_bwd_eth_ip_mf_flags_min = 0
                biflow_bwd_eth_ip_mf_flags_mean = biflow_bwd_eth_ip_mf_flags_std = biflow_bwd_eth_ip_mf_flags_var = 0.0
            else:
                biflow_bwd_eth_ip_mf_flags_total = round(sum(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_mean = round(np.mean(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_std = round(np.std(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_var = round(np.var(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_max = round(max(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_min = round(min(biflow_bwd_eth_ip_mf_flags), 3)

            # ==========================
            # L4 Protocol Specific Genes
            # ==========================
            if l4_protocol:
                # ========================
                # L4 Data Packet Frequency
                # ========================
                if biflow_any_duration == 0:
                    biflow_any_eth_ipv4_l4_data_packets_per_sec = biflow_fwd_eth_ipv4_l4_data_packets_per_sec = \
                        biflow_bwd_eth_ipv4_l4_data_packets_per_sec = 0.0
                else:
                    biflow_any_eth_ipv4_l4_data_packets_per_sec = round(biflow_any_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                    biflow_fwd_eth_ipv4_l4_data_packets_per_sec = round(biflow_fwd_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                    biflow_bwd_eth_ipv4_l4_data_packets_per_sec = round(biflow_bwd_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                
                # =================
                # L4 HEADER LENGTHS
                # =================
                biflow_any_eth_ipv4_l4_header_len_total = round(sum(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_std = round(np.std(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_var = round(np.var(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_max = round(max(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_min = round(min(biflow_any_eth_ipv4_l4_header_lens), 3)

                biflow_fwd_eth_ipv4_l4_header_len_total = round(sum(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_std = round(np.std(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_var = round(np.var(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_max = round(max(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_min = round(min(biflow_fwd_eth_ipv4_l4_header_lens), 3)

                if len(biflow_bwd_eth_ipv4_l4_header_lens) == 0:
                    biflow_bwd_eth_ipv4_l4_header_len_total = biflow_bwd_eth_ipv4_l4_header_len_max = biflow_bwd_eth_ipv4_l4_header_len_min = 0
                    biflow_bwd_eth_ipv4_l4_header_len_mean = biflow_bwd_eth_ipv4_l4_header_len_std = biflow_bwd_eth_ipv4_l4_header_len_var = 0.0
                else:
                    biflow_bwd_eth_ipv4_l4_header_len_total = round(sum(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_std = round(np.std(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_var = round(np.var(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_max = round(max(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_min = round(min(biflow_bwd_eth_ipv4_l4_header_lens), 3)

                # ===============
                # L4 DATA LENGTHS
                # ===============
                biflow_any_eth_ipv4_l4_data_len_total = round(sum(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_std = round(np.std(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_var = round(np.var(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_max = round(max(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_min = round(min(biflow_any_eth_ipv4_l4_data_lens), 3)

                biflow_fwd_eth_ipv4_l4_data_len_total = round(sum(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_std = round(np.std(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_var = round(np.var(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_max = round(max(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_min = round(min(biflow_fwd_eth_ipv4_l4_data_lens), 3)

                if len(biflow_bwd_eth_ipv4_l4_data_lens) == 0:
                    biflow_bwd_eth_ipv4_l4_data_len_total = biflow_bwd_eth_ipv4_l4_data_len_max = biflow_bwd_eth_ipv4_l4_data_len_min = 0
                    biflow_bwd_eth_ipv4_l4_data_len_mean = biflow_bwd_eth_ipv4_l4_data_len_std = biflow_bwd_eth_ipv4_l4_data_len_var = 0.0
                else:
                    biflow_bwd_eth_ipv4_l4_data_len_total = round(sum(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_std = round(np.std(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_var = round(np.var(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_max = round(max(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_min = round(min(biflow_bwd_eth_ipv4_l4_data_lens), 3)

                # =======================================
                # UDP Protocol Specific Genes: COULD-TODO
                # =======================================
                if l4_protocol=="UDP":
                    pass
                # ===========================
                # TCP Protocol Specific Genes
                # ===========================
                elif l4_protocol == "TCP":
                    # =========
                    # FIN FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_max = round(max(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_min = round(min(biflow_any_eth_ipv4_tcp_fin_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_fin_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_fin_flags_total = biflow_bwd_eth_ipv4_tcp_fin_flags_max = biflow_bwd_eth_ipv4_tcp_fin_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_fin_flags_mean = biflow_bwd_eth_ipv4_tcp_fin_flags_std = biflow_bwd_eth_ipv4_tcp_fin_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)

                    # =========
                    # SYN FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_max = round(max(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_min = round(min(biflow_any_eth_ipv4_tcp_syn_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_syn_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_syn_flags_total = biflow_bwd_eth_ipv4_tcp_syn_flags_max = biflow_bwd_eth_ipv4_tcp_syn_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_syn_flags_mean = biflow_bwd_eth_ipv4_tcp_syn_flags_std = biflow_bwd_eth_ipv4_tcp_syn_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)

                    # =========
                    # RST FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_max = round(max(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_min = round(min(biflow_any_eth_ipv4_tcp_rst_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_rst_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_rst_flags_total = biflow_bwd_eth_ipv4_tcp_rst_flags_max = biflow_bwd_eth_ipv4_tcp_rst_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_rst_flags_mean = biflow_bwd_eth_ipv4_tcp_rst_flags_std = biflow_bwd_eth_ipv4_tcp_rst_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)

                    # =========
                    # PSH FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_max = round(max(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_min = round(min(biflow_any_eth_ipv4_tcp_psh_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_psh_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_psh_flags_total = biflow_bwd_eth_ipv4_tcp_psh_flags_max = biflow_bwd_eth_ipv4_tcp_psh_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_psh_flags_mean = biflow_bwd_eth_ipv4_tcp_psh_flags_std = biflow_bwd_eth_ipv4_tcp_psh_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)

                    # =========
                    # ACK FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_max = round(max(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_min = round(min(biflow_any_eth_ipv4_tcp_ack_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ack_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_ack_flags_total = biflow_bwd_eth_ipv4_tcp_ack_flags_max = biflow_bwd_eth_ipv4_tcp_ack_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_ack_flags_mean = biflow_bwd_eth_ipv4_tcp_ack_flags_std = biflow_bwd_eth_ipv4_tcp_ack_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)

                    # =========
                    # URG FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_max = round(max(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_min = round(min(biflow_any_eth_ipv4_tcp_urg_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_urg_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_urg_flags_total = biflow_bwd_eth_ipv4_tcp_urg_flags_max = biflow_bwd_eth_ipv4_tcp_urg_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_urg_flags_mean = biflow_bwd_eth_ipv4_tcp_urg_flags_std = biflow_bwd_eth_ipv4_tcp_urg_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)

                    # =========
                    # ECE FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_max = round(max(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_min = round(min(biflow_any_eth_ipv4_tcp_ece_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ece_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_ece_flags_total = biflow_bwd_eth_ipv4_tcp_ece_flags_max = biflow_bwd_eth_ipv4_tcp_ece_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_ece_flags_mean = biflow_bwd_eth_ipv4_tcp_ece_flags_std = biflow_bwd_eth_ipv4_tcp_ece_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)

                    # =========
                    # CWR FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_any_eth_ipv4_tcp_cwr_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_cwr_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_total = biflow_bwd_eth_ipv4_tcp_cwr_flags_max = biflow_bwd_eth_ipv4_tcp_cwr_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_mean = biflow_bwd_eth_ipv4_tcp_cwr_flags_std = biflow_bwd_eth_ipv4_tcp_cwr_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                else:
                    print("No L4 protocol specified.", flush=True)
                    sys.exit(1)
            # ===============
            # WRAP-UP RESULTS
            # ===============
            biflow_local_vars = locals()
            biflow_genes = [str(biflow_local_vars[var_name]) for var_name in ipv4_all_biflow_genes_header_list]

            yield biflow_genes

    # IPv4-UDP Genes Generator
    ipv4_udp_biflow_genes_generator = calculate_l3_l4_biflow_genes(ipv4_udp_biflows, ipv4_udp_biflow_ids, l4_protocol="UDP")
    # IPv4-TCP Genes Generator
    ipv4_tcp_biflow_genes_generator = calculate_l3_l4_biflow_genes(ipv4_tcp_biflows, ipv4_tcp_biflow_ids,\
        l4_protocol="TCP", l4_conceptual_features=rfc793_tcp_biflow_conceptual_features)

    # can return a listed yelder since passive analysis (threat hunting) is the objective
    # https://stackoverflow.com/questions/3487802/which-is-generally-faster-a-yield-or-an-append
    return list(ipv4_udp_biflow_genes_generator), list(ipv4_tcp_biflow_genes_generator)

def output_net_genes(ipv4_udp_net_genes_generator_lst, ipv4_tcp_net_genes_generator_lst, network_object_type):
    """ Output all network objects present on a PCAP file: biflows, bitalkers and unihosts, along with
    their respective genes (NetGenes): conceptual and statistical features. """

    ipv4_net_genes_header_lst = get_network_object_header(network_object_type, "ipv4")
    ipv4_l4_net_genes_header_lst = get_network_object_header(network_object_type, "ipv4-l4")
    
    ipv4_udp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst
    ipv4_tcp_net_genes_header_lst = ipv4_net_genes_header_lst + ipv4_l4_net_genes_header_lst +\
        get_network_object_header(network_object_type, "ipv4-tcp")

    if args.output_type == "csv":
        def save_csv_file(net_genes_header_lst, net_genes_generator_lst, csv_filename):
            # CSV Header
            net_genes_header_str = "|".join(net_genes_header_lst)
            # CSV Rows
            net_genes_str_lst = ["|".join(net_genes) for net_genes in net_genes_generator_lst]
            net_genes_output = net_genes_header_str + "\n" + "\n".join(net_genes_str_lst)

            # Save CSV File
            f = open(netmeter_globals.csv_output_dir + os.sep + csv_filename, "w")
            f.write(net_genes_output)
            f.close()
        # CSV Directory
        os.makedirs(netmeter_globals.csv_output_dir, exist_ok=True)
        # Save NetGenes
        save_csv_file(ipv4_udp_net_genes_header_lst, ipv4_udp_net_genes_generator_lst, "ipv4-udp-%ss.csv"%(network_object_type))
        save_csv_file(ipv4_tcp_net_genes_header_lst, ipv4_tcp_net_genes_generator_lst, "ipv4-tcp-%ss.csv"%(network_object_type))

def build_l4_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids, ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids):
    """Build L4 UniTalkers"""
    def build_unitalkers(biflow_genes_generator_lst, biflow_ids):
        """Build UniTalkers"""
        unitalkers = dict()
        unitalker_ids = list()

        for biflow_genes in biflow_genes_generator_lst:
            biflow_id_str = biflow_genes[0]
            biflow_id = str_to_iterator(biflow_id_str)
            unitalker_id = biflow_id_to_bitalker_id(biflow_id)

            try:
                unitalkers[unitalker_id].append(biflow_genes)
            except KeyError:
                unitalker_ids.append(unitalker_id)
                unitalkers[unitalker_id] = [biflow_genes]

        return unitalkers, unitalker_ids

    udp_unitalkers, udp_unitalker_ids = build_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)
    tcp_unitalkers, tcp_unitalker_ids = build_unitalkers(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)

    return udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids

def build_l4_bitalkers(udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids):
    """Build L4 BiTalkers"""
    def build_bitalkers(l4_unitalkers, l4_unitalker_ids):
        """Build BiTalkers"""
        def get_unique_matching_l4_unitalker_ids(l4_unitalkers, l4_unitalker_ids):
            """Local helper function to return matching unidirectional talker ids, with l4_fwd_talker_id
            as key and l4_bwd_talker_id as value, and not vice-versa"""
            matching_l4_unitalker_ids_dict = dict()
            l4_fwd_talker_ids = list()
            for l4_unitalker_id in l4_unitalker_ids:
                reversed_l4_unitalker_id = (l4_unitalker_id[1], l4_unitalker_id[0], l4_unitalker_id[2])

                # Note: O(n**2) --> O(n) optimization done using dictionary search
                if reversed_l4_unitalker_id in l4_unitalkers:
                    if reversed_l4_unitalker_id not in matching_l4_unitalker_ids_dict:
                        l4_fwd_talker_ids.append(l4_unitalker_id)
                        matching_l4_unitalker_ids_dict[l4_unitalker_id] = reversed_l4_unitalker_id
                else:
                    if reversed_l4_unitalker_id not in matching_l4_unitalker_ids_dict:
                        l4_fwd_talker_ids.append(l4_unitalker_id)
                        matching_l4_unitalker_ids_dict[l4_unitalker_id] = False
            return matching_l4_unitalker_ids_dict, l4_fwd_talker_ids

        matching_l4_unitalker_ids_dict, l4_fwd_talker_ids = get_unique_matching_l4_unitalker_ids(l4_unitalkers, l4_unitalker_ids)
        l4_bitalkers = dict()
        l4_bitalker_ids = list()

        for l4_fwd_talker_id in l4_fwd_talker_ids:
            # have in mind every l4_unitalker_id in this list will have been constituted by the first flow ever recorded in that talker,
            # so the researcher defines l4_bitalker_id = l4_fwd_talker_id
            l4_bwd_talker_id = matching_l4_unitalker_ids_dict[l4_fwd_talker_id]
            l4_bitalker_ids.append(l4_fwd_talker_id)
            if l4_bwd_talker_id:
                l4_bitalkers[l4_fwd_talker_id] = l4_unitalkers[l4_fwd_talker_id] + l4_unitalkers[l4_bwd_talker_id]
            else:
                l4_bitalkers[l4_fwd_talker_id] = l4_unitalkers[l4_fwd_talker_id]

        return l4_bitalkers, l4_bitalker_ids

    udp_bitalkers, udp_bitalker_ids = build_bitalkers(udp_unitalkers, udp_unitalker_ids)
    tcp_bitalkers, tcp_bitalker_ids = build_bitalkers(tcp_unitalkers, tcp_unitalker_ids)

    return udp_bitalkers, udp_bitalker_ids, tcp_bitalkers, tcp_bitalker_ids

def get_l3_l4_bitalker_gene_generators(udp_bitalkers, udp_bitalker_ids, tcp_bitalkers, tcp_bitalker_ids):
    """Return L3-L4 bitalker gene generators"""
    def calculate_l3_l4_bitalker_genes(bitalkers, bitalker_ids, l4_protocol=None):
        """Calculate and yield L3-L4 bitalker genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_bitalker_genes_header_list = get_network_object_header("bitalker", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_bitalker_genes_header_list = get_network_object_header("bitalker", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_bitalker_genes_header_list = get_network_object_header("bitalker", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_bitalker_genes_header_list = ipv4_bitalker_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_bitalker_genes_header_list += ipv4_l4_bitalker_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_bitalker_genes_header_list += ipv4_tcp_bitalker_genes_header_list

        for bitalker_id in bitalker_ids:
            # ======================
            # Additional Information
            # ======================
            curr_bitalker = bitalkers[bitalker_id]

            first_biflow = curr_bitalker[0]
            last_biflow = curr_bitalker[-1]
            bitalker_any_first_biflow_initiation_time = first_biflow[2]
            bitalker_any_last_biflow_termination_time = last_biflow[3]
            bitalker_any_first_biflow_initiation_time = datetime_to_unixtime(bitalker_any_first_biflow_initiation_time)
            bitalker_any_last_biflow_termination_time = datetime_to_unixtime(bitalker_any_last_biflow_termination_time)

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ======
            # BiFlow
            # ======
            # ----------------------
            # BiFlow Number Features
            # ----------------------
            bitalker_any_n_biflows = len(curr_bitalker)
            bitalker_fwd_n_biflows = 0
            bitalker_bwd_n_biflows = 0

            # ================================
            # BiFlow & Byte Frequency Features
            # ================================
            # done below

            # =============
            # Time Features
            # =============
            bitalker_any_duration = round(\
                (bitalker_any_last_biflow_termination_time - bitalker_any_first_biflow_initiation_time)/time_scale_factor, 3)

            # =========================
            # Destination Port Features
            # =========================
            bitalker_any_biflow_dst_ports = list()
            bitalker_fwd_biflow_dst_ports = list()
            bitalker_bwd_biflow_dst_ports = list()

            # ===============
            # Packet Features
            # ===============
            bitalker_any_biflow_n_packets = list()
            bitalker_fwd_biflow_n_packets = list()
            bitalker_bwd_biflow_n_packets = list()

            # =========================
            # IPv4 Data Length Features
            # =========================
            bitalker_any_biflow_eth_ipv4_data_lens = list()
            bitalker_fwd_biflow_eth_ipv4_data_lens = list()
            bitalker_bwd_biflow_eth_ipv4_data_lens = list()

            # =======================
            # L4 Data Packet Features
            # =======================
            bitalker_any_eth_ipv4_l4_biflow_n_data_packets = list()
            bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets = list()
            bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets = list()

            # =============
            # Time Features
            # =============
            # ----------------
            # BiFlow Durations
            # ----------------
            bitalker_any_biflow_durations = list()
            bitalker_fwd_biflow_durations = list()
            bitalker_bwd_biflow_durations = list()

            # -----------------------------
            # BiFlow Inter-Initiation Times
            # -----------------------------
            bitalker_any_biflow_iits = list()
            bitalker_fwd_biflow_iits = list()
            bitalker_bwd_biflow_iits = list()

            # ------------------------------
            # BiFlow Inter-Termination Times
            # ------------------------------
            bitalker_any_biflow_itts = list()
            bitalker_fwd_biflow_itts = list()
            bitalker_bwd_biflow_itts = list()

            # -----------------------
            # BiFlow Initiation Types
            # -----------------------
            bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()

            # -----------------------
            # BiFlow Connection Types
            # -----------------------
            bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()

            # ------------------------
            # BiFlow Termination Types
            # ------------------------
            bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()

            # =================================
            # Additional Information - Reformat
            # =================================
            # Get unihost_id and convert bitalker_id and unihost_id to strings
            unihost_id = iterator_to_str(bitalker_id_to_unihost_id(bitalker_id))
            bitalker_id = iterator_to_str(bitalker_id)
            bitalker_any_first_biflow_initiation_time = unixtime_to_datetime(bitalker_any_first_biflow_initiation_time)
            bitalker_any_last_biflow_termination_time = unixtime_to_datetime(bitalker_any_last_biflow_termination_time)

            bitalker_any_biflow_n_unique_dst_ports = 0
            bitalker_fwd_biflow_n_unique_dst_ports = 0
            bitalker_bwd_biflow_n_unique_dst_ports = 0
            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_biflow_index = 0
            while curr_biflow_index < bitalker_any_n_biflows:
                # =================
                # BiFlow Concepts |
                # =================
                if curr_biflow_index >= 1:
                    previous_biflow = curr_bitalker[curr_biflow_index-1]
                    previous_biflow_bitalker_id = previous_biflow[1]
                    previous_biflow_initiation_timestamp = previous_biflow[2]
                    previous_biflow_termination_timestamp = previous_biflow[3]

                curr_biflow = curr_bitalker[curr_biflow_index]
                curr_biflow_id_str = curr_biflow[0]
                curr_biflow_id = str_to_iterator(curr_biflow_id_str)
                curr_biflow_bitalker_id_str = curr_biflow[1]
                curr_biflow_initiation_timestamp = curr_biflow[2]
                curr_biflow_termination_timestamp = curr_biflow[3]

                # BiFlow IIT and ITT require that there's at least two biflows
                if curr_biflow_index >= 1:
                    previous_biflow_initiation_time = datetime_to_unixtime(previous_biflow_initiation_timestamp)
                    curr_biflow_initiation_time = datetime_to_unixtime(curr_biflow_initiation_timestamp)
                    curr_biflow_iit = (curr_biflow_initiation_time - previous_biflow_initiation_time)/time_scale_factor
                    bitalker_any_biflow_iits.append(curr_biflow_iit)

                    previous_biflow_termination_time = datetime_to_unixtime(previous_biflow_termination_timestamp)
                    curr_biflow_termination_time = datetime_to_unixtime(curr_biflow_termination_timestamp)
                    curr_biflow_itt = abs( (curr_biflow_termination_time - previous_biflow_termination_time)/time_scale_factor )
                    bitalker_any_biflow_itts.append(curr_biflow_itt)

                    if previous_biflow_bitalker_id == bitalker_id:
                        bitalker_fwd_biflow_iits.append(curr_biflow_iit)
                        bitalker_fwd_biflow_itts.append(curr_biflow_itt)
                    else:
                        bitalker_bwd_biflow_iits.append(curr_biflow_iit)
                        bitalker_bwd_biflow_itts.append(curr_biflow_itt)

                # =============
                # Time Concepts
                # =============
                curr_biflow_duration = float(curr_biflow[4])
                bitalker_any_biflow_durations.append(curr_biflow_duration)

                # ===============
                # Packet Concepts
                # ===============
                curr_biflow_any_n_packets = int(curr_biflow[5])
                bitalker_any_biflow_n_packets.append(curr_biflow_any_n_packets)

                # =============
                # IPv4 Concepts
                # =============
                curr_biflow_ipv4_data_len_total = int(curr_biflow[50])
                bitalker_any_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)

                if curr_biflow_bitalker_id_str == bitalker_id:
                    # Statistical
                    bitalker_fwd_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)
                    bitalker_fwd_biflow_n_packets.append(curr_biflow_any_n_packets)
                    bitalker_fwd_biflow_durations.append(curr_biflow_duration)

                    # Conceptual
                    bitalker_fwd_n_biflows += 1
                else:
                    # Statistical
                    bitalker_bwd_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)
                    bitalker_bwd_biflow_n_packets.append(curr_biflow_any_n_packets)
                    bitalker_bwd_biflow_durations.append(curr_biflow_duration)

                    # Conceptual
                    bitalker_bwd_n_biflows += 1

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    curr_biflow_dst_port = curr_biflow_id[3]
                    curr_biflow_any_eth_ipv4_l4_n_data_packets = int(curr_biflow[104])

                    bitalker_any_biflow_dst_ports.append(curr_biflow_dst_port)
                    bitalker_any_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)
                    if curr_biflow_bitalker_id_str == bitalker_id:
                        bitalker_fwd_biflow_dst_ports.append(curr_biflow_dst_port)
                        bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)
                    else:
                        bitalker_bwd_biflow_dst_ports.append(curr_biflow_dst_port)
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        # DEV-NOTE: "int" function usefully converts True and False into 1 and 0 directly
                        # get initiation type
                        curr_biflow_eth_ipv4_tcp_initiation_two_way_handshake = int(curr_biflow[146]=="True")

                        # get connection type
                        curr_biflow_eth_ipv4_tcp_full_duplex_connection_established = int(curr_biflow[147]=="True")
                        curr_biflow_eth_ipv4_tcp_half_duplex_connection_established = int(curr_biflow[148]=="True")
                        curr_biflow_eth_ipv4_tcp_connection_rejected = int(curr_biflow[149]=="True")
                        curr_biflow_eth_ipv4_tcp_connection_dropped = int(curr_biflow[150]=="True")

                        # get termination type
                        curr_biflow_eth_ipv4_tcp_termination_graceful = int(curr_biflow[151]=="True")
                        curr_biflow_eth_ipv4_tcp_termination_abort = int(curr_biflow[152]=="True")
                        curr_biflow_eth_ipv4_tcp_termination_null = int(curr_biflow[153]=="True")

                        # save initiation type
                        bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_biflow_eth_ipv4_tcp_initiation_two_way_handshake)

                        # save connection type
                        bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_biflow_eth_ipv4_tcp_full_duplex_connection_established)
                        bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_biflow_eth_ipv4_tcp_half_duplex_connection_established)
                        bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_biflow_eth_ipv4_tcp_connection_rejected)
                        bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_biflow_eth_ipv4_tcp_connection_dropped)
                        
                        # save termination type
                        bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_biflow_eth_ipv4_tcp_termination_graceful)
                        bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_biflow_eth_ipv4_tcp_termination_abort)
                        bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_biflow_eth_ipv4_tcp_termination_null)

                # iterate the biflows inside a bitalker
                curr_biflow_index += 1

            # ================================
            # ENRICH AND EXTRACT INFORMATION |
            # ================================
            # ====================
            # Statistical Features
            # ====================
            # ------
            # Packet
            # ------
            bitalker_any_biflow_n_packets_total = round(sum(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_mean = round(np.mean(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_std = round(np.std(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_var = round(np.var(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_max = round(max(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_min = round(min(bitalker_any_biflow_n_packets), 3)

            bitalker_fwd_biflow_n_packets_total = round(sum(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_mean = round(np.mean(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_std = round(np.std(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_var = round(np.var(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_max = round(max(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_min = round(min(bitalker_fwd_biflow_n_packets), 3)

            if len(bitalker_bwd_biflow_n_packets) == 0:
                bitalker_bwd_biflow_n_packets_total = bitalker_bwd_biflow_n_packets_max = bitalker_bwd_biflow_n_packets_min = 0
                bitalker_bwd_biflow_n_packets_mean = bitalker_bwd_biflow_n_packets_std = bitalker_bwd_biflow_n_packets_var = 0.0
            else:
                bitalker_bwd_biflow_n_packets_total = round(sum(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_mean = round(np.mean(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_std = round(np.std(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_var = round(np.var(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_max = round(max(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_min = round(min(bitalker_bwd_biflow_n_packets), 3)

            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(bitalker_any_biflow_eth_ipv4_data_lens), 3)

            bitalker_fwd_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_max = round(max(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_min = round(min(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)

            if len(bitalker_bwd_biflow_eth_ipv4_data_lens) == 0:
                bitalker_bwd_biflow_eth_ipv4_data_lens_total = bitalker_bwd_biflow_eth_ipv4_data_lens_max =\
                    bitalker_bwd_biflow_eth_ipv4_data_lens_min = 0
                bitalker_bwd_biflow_eth_ipv4_data_lens_mean = bitalker_bwd_biflow_eth_ipv4_data_lens_std =\
                    bitalker_bwd_biflow_eth_ipv4_data_lens_var = 0.0
            else:
                bitalker_bwd_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_max = round(max(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_min = round(min(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)

            # ----------------
            # BiFlow Durations
            # ----------------
            bitalker_any_biflow_duration_total = round(sum(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_mean = round(np.mean(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_std = round(np.std(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_var = round(np.var(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_max = round(max(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_min = round(min(bitalker_any_biflow_durations), 3)

            bitalker_fwd_biflow_duration_total = round(sum(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_mean = round(np.mean(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_std = round(np.std(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_var = round(np.var(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_max = round(max(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_min = round(min(bitalker_fwd_biflow_durations), 3)

            if len(bitalker_bwd_biflow_durations) == 0:
                bitalker_bwd_biflow_duration_total = bitalker_bwd_biflow_duration_max = bitalker_bwd_biflow_duration_min = 0
                bitalker_bwd_biflow_duration_mean = bitalker_bwd_biflow_duration_std = bitalker_bwd_biflow_duration_var = 0.0
            else:
                bitalker_bwd_biflow_duration_total = round(sum(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_mean = round(np.mean(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_std = round(np.std(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_var = round(np.var(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_max = round(max(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_min = round(min(bitalker_bwd_biflow_durations), 3)

            # -----------------------------
            # BiFlow Inter-Initiation Times
            # -----------------------------
            # Note: need at least 2 BiFlows to populate BiFlow IITs

            if len(bitalker_any_biflow_iits) == 0:
                bitalker_any_biflow_iit_total = bitalker_any_biflow_iit_max = bitalker_any_biflow_iit_min = 0
                bitalker_any_biflow_iit_mean = bitalker_any_biflow_iit_std = bitalker_any_biflow_iit_var = 0.0
            else:
                bitalker_any_biflow_iit_total = round(sum(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_mean = round(np.mean(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_std = round(np.std(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_var = round(np.var(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_max = round(max(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_min = round(min(bitalker_any_biflow_iits), 3)

            if len(bitalker_fwd_biflow_iits) == 0:
                bitalker_fwd_biflow_iit_total = bitalker_fwd_biflow_iit_max = bitalker_fwd_biflow_iit_min = 0
                bitalker_fwd_biflow_iit_mean = bitalker_fwd_biflow_iit_std = bitalker_fwd_biflow_iit_var = 0.0
            else:
                bitalker_fwd_biflow_iit_total = round(sum(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_mean = round(np.mean(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_std = round(np.std(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_var = round(np.var(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_max = round(max(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_min = round(min(bitalker_fwd_biflow_iits), 3)

            if len(bitalker_bwd_biflow_iits) == 0:
                bitalker_bwd_biflow_iit_total = bitalker_bwd_biflow_iit_max = bitalker_bwd_biflow_iit_min = 0
                bitalker_bwd_biflow_iit_mean = bitalker_bwd_biflow_iit_std = bitalker_bwd_biflow_iit_var = 0.0
            else:
                bitalker_bwd_biflow_iit_total = round(sum(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_mean = round(np.mean(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_std = round(np.std(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_var = round(np.var(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_max = round(max(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_min = round(min(bitalker_bwd_biflow_iits), 3)

            # ------------------------------
            # BiFlow Inter-Termination Times
            # ------------------------------
            # Note: need at least 2 BiFlows to populate BiFlow ITTs
            if len(bitalker_any_biflow_itts) == 0:
                bitalker_any_biflow_itt_total = bitalker_any_biflow_itt_max = bitalker_any_biflow_itt_min = 0
                bitalker_any_biflow_itt_mean = bitalker_any_biflow_itt_std = bitalker_any_biflow_itt_var = 0.0
            else:
                bitalker_any_biflow_itt_total = round(sum(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_mean = round(np.mean(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_std = round(np.std(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_var = round(np.var(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_max = round(max(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_min = round(min(bitalker_any_biflow_itts), 3)

            if len(bitalker_fwd_biflow_itts) == 0:
                bitalker_fwd_biflow_itt_total = bitalker_fwd_biflow_itt_max = bitalker_fwd_biflow_itt_min = 0
                bitalker_fwd_biflow_itt_mean = bitalker_fwd_biflow_itt_std = bitalker_fwd_biflow_itt_var = 0.0
            else:
                bitalker_fwd_biflow_itt_total = round(sum(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_mean = round(np.mean(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_std = round(np.std(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_var = round(np.var(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_max = round(max(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_min = round(min(bitalker_fwd_biflow_itts), 3)

            if len(bitalker_bwd_biflow_itts) == 0:
                bitalker_bwd_biflow_itt_total = bitalker_bwd_biflow_itt_max = bitalker_bwd_biflow_itt_min = 0
                bitalker_bwd_biflow_itt_mean = bitalker_bwd_biflow_itt_std = bitalker_bwd_biflow_itt_var = 0.0
            else:
                bitalker_bwd_biflow_itt_total = round(sum(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_mean = round(np.mean(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_std = round(np.std(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_var = round(np.var(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_max = round(max(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_min = round(min(bitalker_bwd_biflow_itts), 3)

            # ===========
            # L4 Features
            # ===========
            if l4_protocol:
                # -------------------
                # L4 Unique Dst Ports
                # -------------------
                bitalker_any_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_any_biflow_dst_ports))
                bitalker_fwd_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_fwd_biflow_dst_ports))
                bitalker_bwd_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_bwd_biflow_dst_ports))

                bitalker_any_biflow_n_unique_dst_ports = len(bitalker_any_biflow_unique_dst_ports)
                bitalker_fwd_biflow_n_unique_dst_ports = len(bitalker_fwd_biflow_unique_dst_ports)
                bitalker_bwd_biflow_n_unique_dst_ports = len(bitalker_bwd_biflow_unique_dst_ports)

                # ---------------
                # L4 Data Packets
                # ---------------
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)

                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)

                if len(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets) == 0:
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_total = bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_max =\
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_min = 0
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_mean = bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_std =\
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_var = 0.0
                else:
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)

                # =====================
                # TCP BiTalker Features
                # =====================
                if l4_protocol == "TCP":
                    # ---------------------------
                    # TCP BiFlow Initiation Types
                    # ---------------------------
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    # ---------------------------
                    # TCP BiFlow Connection Types
                    # ---------------------------
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    # ----------------------------
                    # TCP BiFlow Termination Types
                    # ----------------------------
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)

            # ==========================
            # Conceptual Features - More
            # ==========================
            # --------------------------------
            # BiFlow & Byte Frequency Features
            # --------------------------------
            if bitalker_any_duration == 0:
                bitalker_any_biflows_per_sec = bitalker_fwd_biflows_per_sec = bitalker_bwd_biflows_per_sec = 0.0
                bitalker_any_biflow_bytes_per_sec = bitalker_fwd_biflow_bytes_per_sec = bitalker_bwd_biflow_bytes_per_sec = 0.0
            else:
                bitalker_any_biflows_per_sec = round(bitalker_any_n_biflows/bitalker_any_duration, 3)
                bitalker_fwd_biflows_per_sec = round(bitalker_fwd_n_biflows/bitalker_any_duration, 3)
                bitalker_bwd_biflows_per_sec = round(bitalker_bwd_n_biflows/bitalker_any_duration, 3)
                bitalker_any_biflow_bytes_per_sec = round(bitalker_any_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)
                bitalker_fwd_biflow_bytes_per_sec = round(bitalker_fwd_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)
                bitalker_bwd_biflow_bytes_per_sec = round(bitalker_bwd_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)

            # ===============
            # WRAP-UP RESULTS
            # ===============
            bitalker_local_vars = locals()
            bitalker_genes = [str(bitalker_local_vars[var_name]) for var_name in ipv4_all_bitalker_genes_header_list]
            
            yield bitalker_genes

    ipv4_udp_bitalker_genes_generator = calculate_l3_l4_bitalker_genes(udp_bitalkers, udp_bitalker_ids, "UDP")
    ipv4_tcp_bitalker_genes_generator = calculate_l3_l4_bitalker_genes(tcp_bitalkers, tcp_bitalker_ids, "TCP")

    return list(ipv4_udp_bitalker_genes_generator), list(ipv4_tcp_bitalker_genes_generator)

def build_l4_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids, ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids):
    """Build L4 UniHosts"""
    def build_unihosts(bitalker_genes_generator_lst, bitalker_ids):
        """Build UniHosts"""
        # Note: l4_unihost_ids in both directions are the same as l4_unihost_ids
        unihosts = dict()
        unihost_ids = list()

        for bitalker_genes in bitalker_genes_generator_lst:
            bitalker_id_str = bitalker_genes[0]
            bitalker_id = str_to_iterator(bitalker_id_str)
            fwd_unihost_id = bitalker_id_to_unihost_id(bitalker_id)
            bwd_unihost_id = bitalker_id_to_unihost_id(bitalker_id, _reversed=True)

            try:
                unihosts[fwd_unihost_id].append(bitalker_genes)
            except KeyError:
                unihost_ids.append(fwd_unihost_id)
                unihosts[fwd_unihost_id] = [bitalker_genes]

        return unihosts, unihost_ids

    udp_unihosts, udp_unihost_ids = build_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)
    tcp_unihosts, tcp_unihost_ids = build_unihosts(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

    return udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids

def get_l3_l4_unihost_gene_generators(udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids):
    """Return L3-L4 unihost gene generators"""
    def calculate_l3_l4_unihost_genes(unihosts, unihost_ids, l4_protocol=None):
        """Calculate and yield L3-L4 unihost genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_unihost_genes_header_list = get_network_object_header("unihost", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_unihost_genes_header_list = get_network_object_header("unihost", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_unihost_genes_header_list = get_network_object_header("unihost", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_unihost_genes_header_list = ipv4_unihost_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_unihost_genes_header_list += ipv4_l4_unihost_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_unihost_genes_header_list += ipv4_tcp_unihost_genes_header_list

        for unihost_id in unihost_ids:
            # ======================
            # Additional Information
            # ======================
            curr_unihost = unihosts[unihost_id]

            first_bitalker = curr_unihost[0]
            last_bitalker = curr_unihost[-1]
            unihost_first_bitalker_initiation_time = first_bitalker[2]
            unihost_last_bitalker_termination_time = last_bitalker[3]
            unihost_first_bitalker_initiation_time = datetime_to_unixtime(unihost_first_bitalker_initiation_time)
            unihost_last_bitalker_termination_time = datetime_to_unixtime(unihost_last_bitalker_termination_time)

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ============================
            # BiTalker Conceptual Features
            # ============================
            # ------------------------
            # BiTalker Number Features
            # ------------------------
            unihost_n_bitalkers = len(curr_unihost)

            # -------------
            # Time Features
            # -------------
            unihost_duration = round((unihost_last_bitalker_termination_time - unihost_first_bitalker_initiation_time)/time_scale_factor, 3)

            # ---------------------------
            # BiTalker Frequency Features
            # ---------------------------
            unihost_bitalkers_per_sec = 0 if unihost_duration == 0 else round(unihost_n_bitalkers/unihost_duration, 3)

            # ---------------------------------
            # Additional Information - Reformat
            # ---------------------------------
            # Convert unihost_id to string
            unihost_id = iterator_to_str(unihost_id)
            unihost_first_bitalker_initiation_time = unixtime_to_datetime(unihost_first_bitalker_initiation_time)
            unihost_last_bitalker_termination_time = unixtime_to_datetime(unihost_last_bitalker_termination_time)

            # =============================
            # BiTalker Statistical Features
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            unihost_bitalker_any_biflow_eth_ipv4_data_lens = list()

            # --------------------
            # L4 Destination Ports
            # --------------------
            unihost_bitalker_any_biflow_n_unique_dst_ports = list()
            unihost_bitalker_fwd_biflow_n_unique_dst_ports = list()
            unihost_bitalker_bwd_biflow_n_unique_dst_ports = list()

            # ---------------------
            # TCP Innitiation Types
            # ---------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()

            # --------------------
            # TCP Connection Types
            # --------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()

            # ---------------------
            # TCP Termination Types
            # ---------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_bitalker_index = 0
            while curr_bitalker_index < unihost_n_bitalkers:
                # ===================
                # BiTalker Concepts |
                # ===================
                if curr_bitalker_index >= 1:
                    previous_bitalker = curr_unihost[curr_bitalker_index-1]
                    previous_bitalker_bitalker_id = previous_bitalker[1]
                    previous_bitalker_initiation_timestamp = previous_bitalker[2]
                    previous_bitalker_termination_timestamp = previous_bitalker[3]

                curr_bitalker = curr_unihost[curr_bitalker_index]
                curr_bitalker_id_str = curr_bitalker[0]
                curr_bitalker_id = str_to_iterator(curr_bitalker_id_str)
                curr_bitalker_bitalker_id_str = curr_bitalker[1]
                curr_bitalker_initiation_timestamp = curr_bitalker[2]
                curr_bitalker_termination_timestamp = curr_bitalker[3]

                # ------------------
                # IPv4 Data Lengthes
                # ------------------
                curr_bitalker_any_biflow_eth_ipv4_data_lens_total = int(curr_bitalker[14])
                unihost_bitalker_any_biflow_eth_ipv4_data_lens.append(curr_bitalker_any_biflow_eth_ipv4_data_lens_total)

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    # --------------------
                    # L4 Destination Ports
                    # --------------------
                    curr_bitalker_any_biflow_n_unique_dst_ports = int(curr_bitalker[104])
                    curr_bitalker_fwd_biflow_n_unique_dst_ports = int(curr_bitalker[105])
                    curr_bitalker_bwd_biflow_n_unique_dst_ports = int(curr_bitalker[106])
                    unihost_bitalker_any_biflow_n_unique_dst_ports.append(curr_bitalker_any_biflow_n_unique_dst_ports)
                    unihost_bitalker_fwd_biflow_n_unique_dst_ports.append(curr_bitalker_fwd_biflow_n_unique_dst_ports)
                    unihost_bitalker_bwd_biflow_n_unique_dst_ports.append(curr_bitalker_bwd_biflow_n_unique_dst_ports)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        # --------------------
                        # TCP Initiation Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = int(curr_bitalker[125])
                        unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations)

                        # --------------------
                        # TCP Connection Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = int(curr_bitalker[131])
                        unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = int(curr_bitalker[137])
                        unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected = int(curr_bitalker[143])
                        unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped = int(curr_bitalker[149])
                        unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped)

                        # ---------------------
                        # TCP Termination Types
                        # ---------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_null_terminations = int(curr_bitalker[155])
                        unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_null_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = int(curr_bitalker[161])
                        unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations = int(curr_bitalker[167])
                        unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations)
                # iterate the bitalkers inside a unihost
                curr_bitalker_index += 1

            # =============================
            # Statistical Features - Calc |
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)

            # ===========
            # L4 Concepts
            # ===========
            if l4_protocol:
                # --------------------
                # L4 Destination Ports
                # --------------------
                unihost_bitalker_any_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)

                unihost_bitalker_fwd_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)

                unihost_bitalker_bwd_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)

                # ============
                # TCP Concepts
                # ============
                if l4_protocol == "TCP":
                    # ------------------------------
                    # TCP BiTalker Innitiation Types
                    # ------------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    # -----------------------------
                    # TCP BiTalker Connection Types
                    # -----------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    # ------------------------------
                    # TCP BiTalker Termination Types
                    # ------------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
            # ==========================
            # Conceptual Features - More
            # ==========================
            # --------------------------------
            # BiTalker Byte Frequency Features
            # --------------------------------
            unihost_bitalker_bytes_per_sec = 0 if unihost_duration == 0 else\
                round(unihost_bitalker_any_biflow_eth_ipv4_data_lens_total/unihost_duration, 3)

            # ===============
            # WRAP-UP RESULTS
            # ===============
            unihost_local_vars = locals()
            unihost_genes = [str(unihost_local_vars[var_name]) for var_name in ipv4_all_unihost_genes_header_list]

            yield unihost_genes

    ipv4_udp_unihost_genes_generator = calculate_l3_l4_unihost_genes(udp_unihosts, udp_unihost_ids, "UDP")
    ipv4_tcp_unihost_genes_generator = calculate_l3_l4_unihost_genes(tcp_unihosts, tcp_unihost_ids, "TCP")

    return list(ipv4_udp_unihost_genes_generator), list(ipv4_tcp_unihost_genes_generator)

def generate_network_objets(input_file):
    """
    Build all network objects: packets, flows, bitalkers and hosts
    """
    if args.verbose:
        run_init_time = time.time()
        print(make_header_string("1. Packet Construction", "=", "=", big_header_factor=2), flush=True)

    # =======
    # Packets
    # =======
    packet_genes = build_packets(input_file, args)

    # =====
    # Flows
    # =====
    if args.verbose:
        print(make_header_string("2. Layer-3/Layer-4 Bidirectional Flow Construction", "=", "=", big_header_factor=2), flush=True)

    # ====================
    # Unidirectional Flows
    # ====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.1. Layer-3 Unidirectional Flows: IPv4"), flush=True)

    l3_uniflows, l3_uniflow_ids = build_l3_uniflows(packet_genes)
    del(packet_genes)

    if args.verbose:
        n_preserved_packets = sum([len(l3_uniflows[l3_uniflow_id]) for l3_uniflow_id in l3_uniflow_ids])
        print("[+] Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] Flows detected:" + Colors.GREEN, len(l3_uniflow_ids), "IPv4 UniFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ===================
    # Bidirectional Flows
    # ===================

    # -------
    # Layer 3
    # -------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.2. Layer-3 Bidirectional Flows: IPv4"), flush=True)

    l3_biflows, l3_biflow_ids = build_l3_biflows(l3_uniflows, l3_uniflow_ids)
    del(l3_uniflows, l3_uniflow_ids)

    if args.verbose:
        n_preserved_packets = sum([len(l3_biflows[l3_biflow_id]) for l3_biflow_id in l3_biflow_ids])
        print("[+] IPv4 Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] IPv4 BiFlows detected:" + Colors.GREEN, len(l3_biflows), "IPv4 BiFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # -------
    # Layer 4
    # -------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.3. Layer-3/Layer-4 Bidirectional Flows: IPv4+GenericL4+(UDP|TCP)"), flush=True)

    udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features,\
        n_disconected_rfc793_packets = build_l4_biflows(l3_biflows, l3_biflow_ids, args)
    del(l3_biflows, l3_biflow_ids)

    if args.verbose:
        n_preserved_udp_packets = sum([len(udp_biflows[udp_biflow_id]) for udp_biflow_id in udp_biflow_ids])
        n_preserved_tcp_packets = sum([len(tcp_biflows[tcp_biflow_id]) for tcp_biflow_id in tcp_biflow_ids])

        print("[+] IPv4-UDP Packets preserved:", n_preserved_udp_packets, "IPv4-UDP OK Packets", flush=True)
        print("[+] IPv4-TCP Packets preserved:", n_preserved_tcp_packets, "IPv4-TCP OK Packets", flush=True)
        print("[+] IPv4-TCP Packets disconected:", n_disconected_rfc793_packets, "IPv4-TCP DCed Packets", flush=True)
        print("[+] IPv4-UDP BiFlows detected:" + Colors.GREEN, len(udp_biflows), "IPv4-UDP BiFlows" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiFlows detected:" + Colors.GREEN, len(tcp_biflows), "IPv4-TCP BiFlows" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ==============================
    # IPv4-L4-(UDP|TCP) BiFlow Genes
    # ==============================
    if args.verbose:
        print(make_header_string("3. Layer-3/Layer-4 Bidirectional Flow Genes", "=", "=", big_header_factor=2), flush=True)
    # ------------------------------------------
    # IPv4-L4-(UDP|TCP) BiFlow Gene Calculations
    # ------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("3.1. IPv4+GenericL4+(UDP|TCP) BiFlow Genes"), flush=True)

    ipv4_udp_biflow_genes_generator_lst, ipv4_tcp_biflow_genes_generator_lst =\
        get_l3_l4_biflow_gene_generators(udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features)
    del(udp_biflows, tcp_biflows, rfc793_tcp_biflow_conceptual_features)

    if args.verbose:
        # minus 4 to remove biflow_id, bitalker_id, biflow_any_first_packet_time and biflow_any_last_packet_time
        ipv4_biflow_genes_count = len(get_network_object_header("biflow", "ipv4")) - 4
        ipv4_l4_biflow_genes_count = len(get_network_object_header("biflow", "ipv4-l4"))
        ipv4_tcp_biflow_genes_count = len(get_network_object_header("biflow", "ipv4-tcp"))

        print("[+] Calculated IPv4 BiFlow Genes:", ipv4_biflow_genes_count, "BiFlow Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 BiFlow Genes:", ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count, "BiFlow Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP BiFlow Genes:" + Colors.GREEN, \
            ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count, "BiFlow Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP BiFlow Genes:" + Colors.GREEN, \
            ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count + ipv4_tcp_biflow_genes_count, "BiFlow Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True)

    # ------------------------------------
    # IPv4-L4-(UDP|TCP) BiFlow Gene Output
    # ------------------------------------
    if args.verbose:
        module_init_time = time.time()

    # Output BiFlows
    output_net_genes(ipv4_udp_biflow_genes_generator_lst, ipv4_tcp_biflow_genes_generator_lst, "biflow")

    if args.verbose:
        print("[T] Saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # =========
    # Talkers |
    # =========
    if args.verbose:
        print(make_header_string("4. Layer-3/Layer-4 Talker Construction", "=", "=", big_header_factor=2), flush=True)

    # ======================
    # Unidirectional Talkers
    # ======================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("4.1. IPv4+GenericL4+(UDP|TCP) Unidirectional Talkers"), flush=True)

    udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids = build_l4_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids,\
        ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)
    del(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids, ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_biflows = sum([len(udp_unitalkers[udp_unitalker_id]) for udp_unitalker_id in udp_unitalker_ids])
        n_contemplated_ipv4_tcp_biflows = sum([len(tcp_unitalkers[tcp_unitalker_id]) for tcp_unitalker_id in tcp_unitalker_ids])
        n_ipv4_udp_unitalkers = len(udp_unitalker_ids)
        n_ipv4_tcp_unitalkers = len(tcp_unitalker_ids)

        print("[+] IPv4-UDP BiFlows contemplated:", n_contemplated_ipv4_udp_biflows, "IPv4-UDP BiFlows", flush=True)
        print("[+] IPv4-TCP BiFlows contemplated:", n_contemplated_ipv4_tcp_biflows, "IPv4-TCP BiFlows", flush=True)
        print("[+] IPv4-UDP UniTalkers detected:" + Colors.GREEN, n_ipv4_udp_unitalkers, "IPv4-UDP UniTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP UniTalkers detected:" + Colors.GREEN, n_ipv4_tcp_unitalkers, "IPv4-TCP UniTalkers" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # =====================
    # Bidirectional Talkers
    # =====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("4.2. IPv4+GenericL4+(UDP|TCP) Bidirectional Talkers"), flush=True)

    udp_bitalkers, udp_bitalker_ids, tcp_bitalkers, tcp_bitalker_ids = build_l4_bitalkers(udp_unitalkers, udp_unitalker_ids,\
        tcp_unitalkers, tcp_unitalker_ids)
    del(udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_biflows = sum([len(udp_bitalkers[udp_bitalker_id]) for udp_bitalker_id in udp_bitalker_ids])
        n_contemplated_ipv4_tcp_biflows = sum([len(tcp_bitalkers[tcp_bitalker_id]) for tcp_bitalker_id in tcp_bitalker_ids])
        n_ipv4_udp_bitalkers = len(udp_bitalker_ids)
        n_ipv4_tcp_bitalkers = len(tcp_bitalker_ids)

        print("[+] IPv4-UDP BiFlows contemplated:", n_contemplated_ipv4_udp_biflows, "IPv4-UDP BiFlows", flush=True)
        print("[+] IPv4-TCP BiFlows contemplated:", n_contemplated_ipv4_tcp_biflows, "IPv4-TCP BiFlows", flush=True)
        print("[+] IPv4-UDP BiTalkers detected:" + Colors.GREEN, n_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiTalkers detected:" + Colors.GREEN, n_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================
    # IPv4-L4-(UDP|TCP) BiTalker Genes
    # ================================
    if args.verbose:
        print(make_header_string("5. Layer-3/Layer-4 Bidirectional Talker Genes", "=", "=", big_header_factor=2), flush=True)

    # --------------------------------------------
    # IPv4-L4-(UDP|TCP) BiTalker Gene Calculations
    # --------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("5.1. IPv4+GenericL4+(UDP|TCP) BiTalker Genes"), flush=True)

    ipv4_udp_bitalker_genes_generator_lst, ipv4_tcp_bitalker_genes_generator_lst =\
        get_l3_l4_bitalker_gene_generators(udp_bitalkers, udp_bitalker_ids, tcp_bitalkers, tcp_bitalker_ids)
    del(udp_bitalkers, tcp_bitalkers)

    if args.verbose:
        # minus 4 to remove bitalker_id, unihost_id, bitalker_any_first_biflow_initiation_time
        # and bitalker_any_last_biflow_termination_time
        ipv4_bitalker_genes_count = len(get_network_object_header("bitalker", "ipv4")) - 4
        ipv4_l4_bitalker_genes_count = len(get_network_object_header("bitalker", "ipv4-l4"))
        ipv4_tcp_bitalker_genes_count = len(get_network_object_header("bitalker", "ipv4-tcp"))

        print("[+] Calculated IPv4 BiTalker Genes:", ipv4_bitalker_genes_count, "BiTalker Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 BiTalker Genes:", ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count, "BiTalker Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP BiTalker Genes:" + Colors.GREEN, \
            ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count, "BiTalker Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP BiTalker Genes:" + Colors.GREEN, \
            ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count + ipv4_tcp_bitalker_genes_count, "BiTalker Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # Output BiTalkers
    output_net_genes(ipv4_udp_bitalker_genes_generator_lst, ipv4_tcp_bitalker_genes_generator_lst, "bitalker")

    # =======
    # Hosts |
    # =======
    if args.verbose:
        print(make_header_string("6. Layer-3/Layer-4 Host Construction", "=", "=", big_header_factor=2), flush=True)

    # ====================
    # Unidirectional Hosts
    # ====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("6.1. IPv4+GenericL4+(UDP|TCP) Unidirectional Hosts"), flush=True)

    udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids = build_l4_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids,\
        ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)
    del(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids, ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_bitalkers = sum([len(udp_unihosts[udp_unihost_id]) for udp_unihost_id in udp_unihost_ids])
        n_contemplated_ipv4_tcp_bitalkers = sum([len(tcp_unihosts[tcp_unihost_id]) for tcp_unihost_id in tcp_unihost_ids])
        n_ipv4_udp_unihosts = len(udp_unihost_ids)
        n_ipv4_tcp_unihosts = len(tcp_unihost_ids)

        print("[+] IPv4-UDP BiTalkers contemplated:", n_contemplated_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers", flush=True)
        print("[+] IPv4-TCP BiTalkers contemplated:", n_contemplated_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers", flush=True)
        print("[+] IPv4-UDP UniHosts detected:" + Colors.GREEN, n_ipv4_udp_unihosts, "IPv4-UDP UniHosts" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP UniHosts detected:" + Colors.GREEN, n_ipv4_tcp_unihosts, "IPv4-TCP UniHosts" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================
    # IPv4-L4-(UDP|TCP) UniHost Genes
    # ================================
    if args.verbose:
        print(make_header_string("7. Layer-3/Layer-4 Unidirectional Host Genes", "=", "=", big_header_factor=2), flush=True)

    # --------------------------------------------
    # IPv4-L4-(UDP|TCP) UniHost Gene Calculations
    # --------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("7.1. IPv4+GenericL4+(UDP|TCP) UniHost Genes"), flush=True)

    ipv4_udp_unihost_genes_generator_lst, ipv4_tcp_unihost_genes_generator_lst =\
        get_l3_l4_unihost_gene_generators(udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids)
    del(udp_unihosts, tcp_unihosts)

    if args.verbose:
        # minus 3 to remove unihost_id, unihost_first_bitalker_initiation_time
        # and unihost_first_bitalker_termination_time
        ipv4_unihost_genes_count = len(get_network_object_header("unihost", "ipv4")) - 3
        ipv4_l4_unihost_genes_count = len(get_network_object_header("unihost", "ipv4-l4"))
        ipv4_tcp_unihost_genes_count = len(get_network_object_header("unihost", "ipv4-tcp"))

        print("[+] Calculated IPv4 UniHost Genes:", ipv4_unihost_genes_count, "UniHost Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 UniHost Genes:", ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count, "UniHost Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP UniHost Genes:" + Colors.GREEN, \
            ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count, "UniHost Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP UniHost Genes:" + Colors.GREEN, \
            ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count + ipv4_tcp_unihost_genes_count, "UniHost Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # Output UniHosts
    output_net_genes(ipv4_udp_unihost_genes_generator_lst, ipv4_tcp_unihost_genes_generator_lst, "unihost")

    # ==========
    # FINISHED |
    # ==========
    if args.verbose:
        print(make_header_string("Total Extraction Time", "=", "=", big_header_factor=2), flush=True)
        print("[T] Script took" + Colors.YELLOW, round(time.time() - run_init_time, 3), "seconds" +\
            Colors.ENDC, "to complete", flush=True, end="\n\n")


# ========================================
# END: Generating PCAP Intel - Net Genes |
# ========================================

##====##
##MAIN##
##====##
def run():
    os.makedirs(netmeter_globals.pcapng_files_dir, exist_ok=True)
    os.makedirs(netmeter_globals.csv_files_dir, exist_ok=True)

    print(make_header_string("NetMeter I/O Info", "»", "«", big_header_factor=2), flush=True)
    print("[+] Input PCAP file:"  + Colors.BLUE, args.pcap_path + Colors.ENDC, flush=True)
    pcap_size_bytes = os.path.getsize(args.pcap_path)
    pcap_size_str = get_size_str(pcap_size_bytes)
    if args.output_type == "csv":
        print("[+] Output CSV directory:", Colors.BLUE + netmeter_globals.csv_output_dir +\
            Colors.ENDC, flush=True)
    print("[+] Parsing and working on", Colors.BLUE + pcap_size_str + Colors.ENDC, "of data. Please wait.", flush=True)

    if args.verbose:
        print("")
        print(make_header_string("VERBOSE OUTPUT ACTIVATED", "+", "+", big_header_factor=2), flush=True)
        print(make_header_string("NetMeter Supported Protocols for NetGene Extraction", "-", "-", big_header_factor=2), flush=True)
        print("[+] Layer 1: Ethernet", flush=True)
        print("[+] Layer 2: Ethernet", flush=True)
        print("[+] Layer 3: IPv4", flush=True)
        print("[-] Layer 3+: ICMPv4, IGMPv4", flush=True)
        print("[+] Layer 4: TCP, UDP", flush=True, end="\n\n")

    with open(args.pcap_path, "rb") as input_file:
        generate_network_objets(input_file)

    if args.output_type == "csv":
        csv_output_dir_size = get_dir_size(netmeter_globals.csv_output_dir)
        csv_size_str = get_size_str(csv_output_dir_size)
        print("[+] Network-object (BiFlows, BiTalkers and UniHosts) genes extracted:" + Colors.BLUE,
            csv_size_str + Colors.ENDC, flush=True, end="\n\n")
    

# Reading Command-Line Output:
# [!]: Error Information
# [+]: Normal Information
# [T]: Time Information
# [D]: Debug Information
if __name__ == "__main__":
    args = NetMeterArgs().args
    netmeter_globals = NetMeterGlobals(args)
    run()
