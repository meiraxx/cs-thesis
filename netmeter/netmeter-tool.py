#!/usr/bin/env python3

"""
This script is meant to output "hosts" (ipX), "talkers" (ipX-ipY) and "flows"
(ipX-portA-ipY-portB-protocol_stack-inner_sep_counter), which are network objects,
and their respective conceptual and statistical features to build a dataset.
This conceptual and statistical features are called, in their combination, genes.
NetMeter is the first of the three main tasks of my thesis.

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

# ===================
# Third-party Modules
# ===================
try:
    import dpkt
    import socket, ipaddress, datetime
    import numpy as np
    import time
    import argparse
    import os, sys

    from dpkt.compat import compat_ord
    from collections import OrderedDict
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# =================
# Auxiliary Modules
# =================
try:
    this_script_dirpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, this_script_dirpath + os.sep + "auxiliary-python-modules")
    import cterminal
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")


# ==================
# NetMeter Arguments
# ==================
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
                help_message = help_message.replace("PCAP-File-Path", cterminal.colors.YELLOW + "PCAP-File-Path <-- " + cterminal.colors.ENDC + \
                    cterminal.colors.RED + "Please give me a PCAP file as an input!" + cterminal.colors.ENDC)
                print(help_message, file=sys.stderr, flush=True)
                sys.exit(1)

        def verify_output_type(args):
            """Local helper function to verify output type: csv, mongo, etc."""
            supported_output_types = ("csv",)
            if args.output_type not in supported_output_types:
                print("[!] Specified output type", cterminal.colors.RED + args.output_type + cterminal.colors.ENDC,
                    "is not a valid output type. Valid output types:"  + cterminal.colors.BLUE,
                    ",".join(supported_output_types) + cterminal.colors.ENDC, flush=True)
                sys.exit(1)

        oparser = argparse.ArgumentParser(prog="NetMeter", description="Description: NetGene extraction tool", \
            epilog="For any enquiries, please contact me at joao[dot]meira[dot]cs[at]gmail[dot]com", add_help=False)
        oparser.add_argument("pcap_path", metavar="PCAP-File-Path", nargs="?", help="Input PCAP file", default="")
        oparser.add_argument("-h", "-H", "--help", action="store_true", help="See this help message", dest="print_help")
        oparser.add_argument("-V", "--version", action="version", help="See NetMeter version", version="%(prog)s 1.0")
        oparser.add_argument("-s", "--safe-check", action="store_true", help="Perform safe checks", dest="safe_check")
        oparser.add_argument("-d", "--debug", action="store_true", help="Debug output", dest="debug")
        oparser.add_argument("-v", "--verbose", action="store_true", help="Verbose output", dest="verbose")
        oparser.add_argument("-D", metavar="Data Directory", help="Specify data directory: store inputs (e.g. PCAP) and outputs (e.g. CSV)", dest="data_dir", default="data-files")
        oparser.add_argument("-T", metavar="Output Type", help="Specify output type: mongo, csv, ...", dest="output_type", type=str.lower, default="csv")
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

# ================
# NetMeter Globals
# ================
class NetMeterGlobals:
    def __init__(self, args):
        self.pcap_files_dir = args.data_dir + os.sep + "pcap"
        self.csv_files_dir = args.data_dir + os.sep + "csv"
        # csv output dir is only created when needed
        self.csv_output_dir = self.csv_files_dir + os.sep + os.path.splitext(os.path.basename(args.pcap_path))[0]

# ==========================
# START: Auxiliary Functions
# ==========================

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def flow_id_to_talker_id(flow_id):
    splitted_flow_id = flow_id.split("-")
    return splitted_flow_id[0] + "-" + splitted_flow_id[2]

def generate_flow_line(flow_genes):
    return flow_id_to_str(flow_genes[0]) + "|" + "|".join(map(str,flow_genes[1:]))

def flow_id_to_str(flow_id):
    return "-".join(map(str,flow_id))

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

def make_header_string(string, separator="#", big_header=False):
    """Transforms a string into an header"""
    separator_line = separator*len(string)
    if big_header:
        header_string = cterminal.colors.BOLD + separator_line*2 + "\n" + string + "\n" + separator_line*2 + cterminal.colors.ENDC
    else:
        header_string = cterminal.colors.BOLD + separator_line + "\n" + string + "\n" + separator_line + cterminal.colors.ENDC
    return header_string

# ========================
# END: Auxiliary Functions
# ========================

def build_packets(input_pcap_file, args):
    """Process PCAP and build packets"""

    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("1.1. Packets"), flush=True)
    input_pcap_file.seek(0)
    pcap = dpkt.pcap.Reader(input_pcap_file)
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
    # when introducing mixed NetGenes (l3flows/l4flows/talkers/hosts)
    packets = []
    
    # [+] PARSE ALL PACKETS
    for timestamp, buf in pcap:
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
        # TCP and UDP are the most relevant protocols, so we focus on layer 4 (transport layer)

        # Unpack the data within the IPv4 frame: either TCP or UDP data
        transport_layer = ipv4.data

        # -----------------------
        # TCP/UDP packet genes
        # -----------------------
        # Extracting l4 protocol name
        transport_protocol_name = type(transport_layer).__name__

        # TCP/UDP source and destination ports
        src_port = transport_layer.sport
        dst_port = transport_layer.dport

        # TCP/UDP lengths
        transport_options_len = len(transport_layer.opts) if hasattr(transport_layer, "opts") else 0
        transport_header_len = transport_layer.__hdr_len__
        transport_data_len = len(transport_layer.data)

        # IPv4-L4 Flow Identifier: 6-tuple -> (src ip, src port, dst ip, dst port, protocol_stack, inner_sep_counter)
        # note: inner_sep_counter is incremented whenever a flow reaches its end, which is defined by the protocol used
        flow_id = (src_ip, src_port, dst_ip, dst_port, transport_protocol_name, 0)

        # Packet-level debug Info
        if args.debug:
            print(make_header_string("SINGLE PACKETS INFO"), flush=True)
            print("Packet no.:", packet_no, flush=True)
            print("IPv4 header length:", ipv4_header_len, flush=True)
            print("IPv4 options length:", ipv4_options_len, flush=True)
            print("IPv4 data length:", ipv4_data_len, flush=True)
            print("Transport header length:", transport_header_len, flush=True)
            print("Transport options length:", transport_options_len, flush=True)
            print("Transport data length:", transport_data_len, flush=True)

        packet_genes = [flow_id,] + ipv4_packet_genes
        if transport_protocol_name == "TCP":
            # ===================
            # TCP packet genes
            # ===================
            #https://en.wikipedia.org/wiki/Transmission_Control_Protocol
            #https://tools.ietf.org/html/rfc793

            tcp_fin_flag = ( transport_layer.flags & dpkt.tcp.TH_FIN ) != 0
            tcp_syn_flag = ( transport_layer.flags & dpkt.tcp.TH_SYN ) != 0
            tcp_rst_flag = ( transport_layer.flags & dpkt.tcp.TH_RST ) != 0
            tcp_psh_flag = ( transport_layer.flags & dpkt.tcp.TH_PUSH) != 0
            tcp_ack_flag = ( transport_layer.flags & dpkt.tcp.TH_ACK ) != 0
            tcp_urg_flag = ( transport_layer.flags & dpkt.tcp.TH_URG ) != 0
            tcp_ece_flag = ( transport_layer.flags & dpkt.tcp.TH_ECE ) != 0
            tcp_cwr_flag = ( transport_layer.flags & dpkt.tcp.TH_CWR ) != 0
            tcp_packet_genes = [tcp_fin_flag, tcp_syn_flag, tcp_rst_flag, tcp_psh_flag, tcp_ack_flag, tcp_urg_flag, tcp_ece_flag, tcp_cwr_flag]
            packet_genes += tcp_packet_genes
            packets.append(packet_genes)
        elif transport_protocol_name == "UDP":
            # ================
            # UDP packet genes
            # ================
            #https://pdfs.semanticscholar.org/3648/75dcf14e886a9f9fa9310bb6fd9c8a4f4105.pdf
            # TODO: in case it applies, do udp packet genes
            udp_packet_genes = []
            #packet_genes += udp_packet_genes

    if args.verbose:
        print("[-] EthL1-ARP packets:" + cterminal.colors.RED, n_packets_arp, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] EthL1-LLC packets:" + cterminal.colors.RED, n_packets_llc, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-ICMP packets:" + cterminal.colors.RED, n_packets_eth_ipv4_icmp, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-IGMP packets:" + cterminal.colors.RED, n_packets_eth_ipv4_igmp, "packets" + cterminal.colors.ENDC, flush=True)
        print("[+] EthL1-EthL2-IPv4-TCP packets:" + cterminal.colors.GREEN, n_packets_eth_ipv4_tcp, "packets" + cterminal.colors.ENDC, flush=True)
        print("[+] EthL1-EthL2-IPv4-UDP packets:" + cterminal.colors.GREEN, n_packets_eth_ipv4_udp, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv4-<Other L4> packets:" + cterminal.colors.RED, n_packets_eth_ipv4_others, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] EthL1-EthL2-IPv6 packets:" + cterminal.colors.RED, n_packets_eth_ipv6, "packets" + cterminal.colors.ENDC, flush=True)
        print("[-] <Other L1>, EthL1-<Other L2> and EthL1-EthL2-<Other L3> packets:" + cterminal.colors.RED, n_packets_others, "packets" + cterminal.colors.ENDC, flush=True)
        print("[+] Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")
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
        flow_id = packet[0]
        l3_uniflow_ids.append(flow_id)
        try:
            l3_uniflows[flow_id].append(packet)
        except KeyError:
            l3_uniflows[flow_id] = [packet]
    #remove duplicates mantaining order
    l3_uniflow_ids = list(OrderedDict.fromkeys(l3_uniflow_ids))
    return l3_uniflows, l3_uniflow_ids

def build_l3_biflows(l3_uniflows, l3_uniflow_ids):
    """Join unidirectional flow information into its bidirectional flow equivalent"""
    def get_unique_matching_l3_uniflow_ids(l3_uniflow_ids):
        """Local helper function to return matching unidirectional flow ids, with l3_fwd_flow_id
        as key and l3_bwd_flow_id as value, and not vice-versa"""
        matching_l3_uniflow_ids_dict = dict()
        l3_fwd_flow_ids = list()
        for l3_uniflow_id in l3_uniflow_ids:
            reversed_l3_uniflow_id = (l3_uniflow_id[2], l3_uniflow_id[3], l3_uniflow_id[0],
                l3_uniflow_id[1], l3_uniflow_id[4], l3_uniflow_id[5])
            if reversed_l3_uniflow_id in l3_uniflow_ids:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = reversed_l3_uniflow_id
            else:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = False
        return matching_l3_uniflow_ids_dict, l3_fwd_flow_ids

    matching_l3_uniflow_ids_dict, l3_fwd_flow_ids = get_unique_matching_l3_uniflow_ids(l3_uniflow_ids)
    l3_biflows = dict()
    l3_biflow_ids = list()

    for l3_fwd_flow_id in l3_fwd_flow_ids:
        # have in mind every l3_uniflow_id in this list will have been constituted by the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet, hence l3_uniflow_id = l3_fwd_flow_id
        l3_bwd_flow_id = matching_l3_uniflow_ids_dict[l3_fwd_flow_id]
        l3_biflow_ids.append(l3_fwd_flow_id)
        if l3_bwd_flow_id:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id] + l3_uniflows[l3_bwd_flow_id]
        else:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id]
    return l3_biflows, l3_biflow_ids

class RFC793:
    def __init__(self):
        self.set_initial_connection_state()
        self.inner_sep_counter = 0

    def set_initial_connection_state(self):
        self.tcp_three_way_handshake_phase1 = False
        self.tcp_three_way_handshake_phase2 = False
        self.tcp_three_way_handshake_phase3 = False

        self.tcp_two_way_handshake_phase1 = False
        self.tcp_two_way_handshake_phase2 = False

        self.tcp_graceful_termination_phase1 = False
        self.tcp_graceful_termination_phase2 = False
        self.tcp_graceful_termination_phase3 = False

        self.tcp_abort_termination_phase1 = False
        self.tcp_abort_termination_phase2 = False

def build_l4_biflows(l3_biflows, l3_biflow_ids):
    """Separate layer-3 bidirectional flows by layer-4 protocol and
    build layer-4 bidirectional flows according to TCP and UDP RFCs"""
    def build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids):
        """Local helper function to build TCP BiFlows according to RFC793"""
        # FUTURE-TODO: validate using tcp_seq
        rfc793_tcp_biflows = dict()
        rfc793_tcp_biflow_ids = []

        # create RFC793-compliant TCP flows
        for tmp_tcp_biflow_id in tmp_tcp_biflow_ids:
            curr_flow = tmp_tcp_biflows[tmp_tcp_biflow_id]
            # sorting the packets in each flow by timestamp
            curr_flow.sort(key=lambda x: x[1])
            flow_any_n_packets = len(curr_flow)

            if flow_any_n_packets == 0:
                print("[!] A flow can't have 0 packets.", file=sys.stderr, flush=True)
                sys.exit(1)
            # 1, 2 or 3 packets on a single biflow_id, in any circumstance, represents at most only one tcp flow
            elif (flow_any_n_packets >= 1) and (flow_any_n_packets <= 3):
                rfc793_tcp_biflows[tmp_tcp_biflow_id] = curr_flow
                rfc793_tcp_biflow_ids.append(tmp_tcp_biflow_id)
            else:
                # NEW RFC793-compliant TCP FLOW
                rfc793 = RFC793()
                curr_packet_index = 0
                previous_packet_index = 0
                inner_sep_counter = 0
                flow_begin = False

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
                    
                    # ==================================
                    # TCP FLOW INITIATION RULES - BACKUP
                    # ==================================
                    # r1,r2: begin flow
                    r1 = (syn1 and not ack1) and (syn2 and ack2) and ack3           # 3-way handshake (full-duplex), syn+syn-ack+ack / syn+syn-ack+syn-ack
                    r2 = (syn1 and not ack1) and ack2                               # 2-way handshake (half-duplex), syn+syn-ack / syn+ack

                    # ===================================
                    # TCP FLOW TERMINATION RULES - BACKUP
                    # ===================================
                    # r3,r4: end flow
                    r3 = fin1 and (fin2 and ack2) and ack3                          # graceful termination
                    r4 = rst1 and not rst2                                          # abort termination

                    # ============================
                    # TCP FLOW INITIATION - BACKUP
                    # ============================
                    # consider flow begin or ignore it (considering it is safer, but not considering it will leave out flows that have started before the capture)
                    # the only rule used for flow begin will be the half-duplex handshake rule because it is inclusive of the full-duplex handshake rule,
                    # i.e., (r2 or r1) == r2, for any flow
                    if r2:
                        flow_begin = True

                    # we consider flows only the ones that start with a 2 or 3-way handshake (r1,r2)
                    # the flow end conditions are r3 and r4, (fin,fin-ack,ack)/(rst,!rst,---), or if the packet is the last one of the existing communication
                    if flow_begin:
                        rfc793_tcp_biflow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                            tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + inner_sep_counter)
                        next_packet_index = 0
                        # ====================
                        # TCP FLOW TERMINATION
                        # ====================
                        # graceful termination
                        if r3:
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = curr_flow[previous_packet_index:curr_packet_index+3]
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            flow_begin = False
                            previous_packet_index = curr_packet_index + 3
                            inner_sep_counter += 1
                            flow_tcp_termination_graceful = True
                        else:
                            # abort termination
                            if r4:
                                rfc793_tcp_biflows[rfc793_tcp_biflow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                                rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                                flow_begin = False
                                previous_packet_index = curr_packet_index + 1
                                inner_sep_counter += 1
                                flow_tcp_termination_abort = True
                            # null termination
                            elif curr_packet_index == flow_any_n_packets-1:
                                rfc793_tcp_biflows[rfc793_tcp_biflow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                                rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                                flow_begin = False
                                previous_packet_index = curr_packet_index + 1
                                inner_sep_counter += 1
                                flow_tcp_termination_null = True
                    # keep iterating through the packets
                    curr_packet_index+=1
                    """
                    # =========================
                    # TCP FLOW INITIATION RULES
                    # =========================
                    # Begin Flow: tcp_three_way_handshake, tcp_two_way_handshake
                    # 3-way handshake (full-duplex): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack)
                    rfc793.tcp_three_way_handshake_phase1 = rfc793.tcp_three_way_handshake_phase1 or ((syn1 and not ack1) and (syn2 and ack2) and ack3)
                    rfc793.tcp_three_way_handshake_phase2 = rfc793.tcp_three_way_handshake_phase1 and (rfc793.tcp_three_way_handshake_phase2 or ((syn1 and ack1) and ack2))
                    rfc793.tcp_three_way_handshake_phase3 = rfc793.tcp_three_way_handshake_phase2 and (rfc793.tcp_three_way_handshake_phase3 or ack1)

                    # 2-way handshake (half-duplex): (syn,ack) or (syn,syn-ack)
                    rfc793.tcp_two_way_handshake_phase1 = rfc793.tcp_two_way_handshake_phase1 or ((syn1 and not ack1) and ack2)
                    rfc793.tcp_two_way_handshake_phase2 = rfc793.tcp_two_way_handshake_phase1 and (rfc793.tcp_two_way_handshake_phase2 or ack1)

                    # ==========================
                    # TCP FLOW TERMINATION RULES
                    # ==========================
                    # End Flow: tcp_graceful_termination, tcp_abort_termination
                    # graceful termination
                    rfc793.tcp_graceful_termination_phase1 = rfc793.tcp_graceful_termination_phase1 or (fin1 and (fin2 and ack2) and ack3)
                    rfc793.tcp_graceful_termination_phase2 = rfc793.tcp_graceful_termination_phase1 and (rfc793.tcp_graceful_termination_phase2 or ((fin1 and ack1) and ack2))
                    rfc793.tcp_graceful_termination_phase3 = rfc793.tcp_graceful_termination_phase2 and (rfc793.tcp_graceful_termination_phase3 or ack1)

                    # abort termination
                    rfc793.tcp_abort_termination_phase1 = rfc793.tcp_abort_termination_phase1 or (rst1 and not rst2)
                    rfc793.tcp_abort_termination_phase2 = rfc793.tcp_abort_termination_phase1 and (rfc793.tcp_abort_termination_phase2 or not rst1)

                    # ===================
                    # TCP FLOW INITIATION
                    # ===================
                    # Note: Consider flow begin or ignore it (considering it is safer, but not considering it will
                    # leave out flows that have started before the capture)

                    # Flow start conditions:
                    # S1: 2-way handshake
                    # S2: 3-way handshake
                    #if rfc793.tcp_three_way_handshake_phase3:
                    #    tcp_biflow_initiated = True
                    #elif rfc793.tcp_two_way_handshake_phase2:
                    #    tcp_biflow_initiated = True

                    # Flow end conditions are:
                    # E1: (fin,fin-ack,ack)
                    # E2: (rst,!rst,---)
                    # E3:the packet is the last one of the existing communication
                    if rfc793.tcp_three_way_handshake_phase3:
                        tcp_flow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                            tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + rfc793.inner_sep_counter)
                        next_packet_index = 0
                        # ====================
                        # TCP FLOW TERMINATION
                        # ====================
                        # graceful termination
                        if rfc793.tcp_graceful_termination_phase3:
                            rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+3]
                            rfc793_tcp_biflow_ids.append(tcp_flow_id)
                            previous_packet_index = curr_packet_index + 3
                            rfc793.inner_sep_counter += 1

                            rfc793.tcp_graceful_termination_phase1 = False
                            rfc793.tcp_graceful_termination_phase2 = False
                            rfc793.tcp_graceful_termination_phase3 = False
                        else:
                            # abort termination
                            if rfc793.tcp_abort_termination_phase2:
                                rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                                rfc793_tcp_biflow_ids.append(tcp_flow_id)
                                previous_packet_index = curr_packet_index + 1
                                rfc793.inner_sep_counter += 1
                            # null termination
                            elif curr_packet_index == flow_any_n_packets-1:
                                rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                                rfc793_tcp_biflow_ids.append(tcp_flow_id)
                                previous_packet_index = curr_packet_index + 1
                                rfc793.inner_sep_counter += 1
                    # keep iterating through the packets
                    curr_packet_index+=1
                    """
        return rfc793_tcp_biflows, rfc793_tcp_biflow_ids

    # ==================================
    # Separate L3 BiFlows by L4 protocol
    # ==================================
    udp_biflows, udp_biflow_ids = dict(), list()
    tmp_tcp_biflows, tmp_tcp_biflow_ids = dict(), list()
    for l3_biflow_id in l3_biflow_ids:
        biflow = l3_biflows[l3_biflow_id]
        transport_protocol_name = l3_biflow_id[4]
        if transport_protocol_name=="UDP":
            udp_biflows[l3_biflow_id] = biflow
            udp_biflow_ids.append(l3_biflow_id)
        elif transport_protocol_name=="TCP":
            tmp_tcp_biflows[l3_biflow_id] = biflow
            tmp_tcp_biflow_ids.append(l3_biflow_id)
        else:
            print("ERROR: Run-time should never reach this branch, but in case it does, it means that another protocol was let through in an earlier stage.",
                file=sys.stderr, flush=True)
            sys.exit(1)

    # Apply RFC793 to the unseparated TCP BiFlows
    tcp_biflows, tcp_biflow_ids = build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids)
    #tcp_biflows, tcp_biflow_ids = tmp_tcp_biflows, tmp_tcp_biflow_ids
    return udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids

def get_biflow_header_by_type(protocol_stack):
    genes_dir = "network-objects" + os.sep + "genes"
    genes_header_str = ""
    if protocol_stack == "ipv4":
        genes_file = genes_dir + os.sep + "ipv4-biflow-header.txt"
    else:
        print("[!] Protocol stack \"" + protocol_stack + "\" not supported. Supported protocol stacks: ipv4", file=sys.stderr, flush=True)
        sys.exit(1)

    f = open(genes_file, "r")
    genes_header_str = f.read().replace("\n", "|")
    f.close()

    return genes_header_str

def calculate_l3_l4_biflow_genes(biflows, biflow_ids):
    """Calculate and output IPv4 biflow genes"""
    time_scale_factor = 1000.0
    ipv4_biflow_genes_header_str = get_biflow_header_by_type("ipv4")
    ipv4_biflow_genes_header_list = ipv4_biflow_genes_header_str.split("|")

    # Note: in case of a bug, use "biflow_no" to debug
    for biflow_no, biflow_id in enumerate(biflow_ids):
        curr_biflow = biflows[biflow_id]
        # DEV-NOTE: curr_biflow[packet_index][packet_gene_index]
        # NOTE: backward packets may not exist

        # =========================
        # PREPARE DATA STRUCTURES |
        # =========================

        # ======================
        # Packet Number Features
        # ======================
        biflow_any_n_packets = len(curr_biflow)
        biflow_fwd_n_packets = 0
        biflow_bwd_n_packets = 0

        biflow_any_n_data_packets = 0
        biflow_fwd_n_data_packets = 0
        biflow_bwd_n_data_packets = 0

        # ===============
        # Length Features
        # ===============
        biflow_any_eth_ipv4_data_lens = list()
        biflow_fwd_eth_ipv4_data_lens = list()
        biflow_bwd_eth_ipv4_data_lens = list()

        biflow_any_eth_ipv4_header_lens = list()
        biflow_fwd_eth_ipv4_header_lens = list()
        biflow_bwd_eth_ipv4_header_lens = list()

        # ======================
        # IP Fragmentation Flags
        # ======================
        biflow_any_eth_ipv4_df_flags = list()
        biflow_fwd_eth_ipv4_df_flags = list()
        biflow_bwd_eth_ipv4_df_flags = list()

        biflow_any_eth_ipv4_mf_flags = list()
        biflow_fwd_eth_ipv4_mf_flags = list()
        biflow_bwd_eth_ipv4_mf_flags = list()

        # =============
        # Time Features
        # =============
        biflow_any_iats = list()
        biflow_fwd_iats = list()
        biflow_bwd_iats = list()

        # ==========================
        # POPULATE DATA STRUCTURES |
        # ==========================
        curr_packet_index = 0
        while curr_packet_index < biflow_any_n_packets:
            previous_packet = curr_biflow[curr_packet_index-1]
            previous_packet_biflow_id = previous_packet[0]
            previous_packet_timestamp = previous_packet[1]

            curr_packet = curr_biflow[curr_packet_index]
            curr_packet_biflow_id = curr_packet[0]
            curr_packet_timestamp = curr_packet[1]
            curr_packet_eth_ipv4_header_len = curr_packet[2]
            curr_packet_eth_ipv4_data_len = curr_packet[3]
            curr_packet_df_flag = curr_packet[4]
            curr_packet_mf_flag = curr_packet[5]

            # IAT requires that there's at least two packets.
            if curr_packet_index >= 1:
                curr_packet_time = datetime_to_unixtime(previous_packet_timestamp)
                next_packet_time = datetime_to_unixtime(curr_packet_timestamp)
                curr_packet_iat = (next_packet_time - curr_packet_time)/time_scale_factor
                biflow_any_iats.append(curr_packet_iat)
                if previous_packet_biflow_id == biflow_id:
                    biflow_fwd_iats.append(curr_packet_iat)
                else:
                    biflow_bwd_iats.append(curr_packet_iat)

            biflow_any_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
            biflow_any_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
            biflow_any_eth_ipv4_df_flags.append(curr_packet_df_flag)
            biflow_any_eth_ipv4_mf_flags.append(curr_packet_mf_flag)

            if curr_packet_biflow_id == biflow_id:
                biflow_fwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                biflow_fwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                biflow_fwd_eth_ipv4_df_flags.append(curr_packet_df_flag)
                biflow_fwd_eth_ipv4_mf_flags.append(curr_packet_mf_flag)

                biflow_fwd_n_packets += 1
                if curr_packet_eth_ipv4_header_len != curr_packet_eth_ipv4_data_len:
                    biflow_any_n_data_packets += 1
                    biflow_fwd_n_data_packets += 1
            else:
                biflow_bwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                biflow_bwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                biflow_bwd_eth_ipv4_df_flags.append(curr_packet_df_flag)
                biflow_bwd_eth_ipv4_mf_flags.append(curr_packet_mf_flag)

                biflow_bwd_n_packets += 1
                if curr_packet_eth_ipv4_header_len != curr_packet_eth_ipv4_data_len:
                    biflow_any_n_data_packets += 1
                    biflow_bwd_n_data_packets += 1

            curr_packet_index+=1

        # ================================
        # ENRICH AND EXTRACT INFORMATION |
        # ================================

        # ======================
        # ADDITIONAL INFORMATION
        # ======================
        first_packet = curr_biflow[0]
        last_packet = curr_biflow[biflow_any_n_packets-1]
        first_packet_timestamp = first_packet[1]
        last_packet_timestamp = last_packet[1]

        biflow_any_first_packet_time = datetime_to_unixtime(first_packet_timestamp)
        biflow_any_last_packet_time = datetime_to_unixtime(last_packet_timestamp)

        # ==============
        # Packet Lengths
        # ==============
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
            biflow_bwd_eth_ipv4_data_len_total = biflow_bwd_eth_ipv4_data_len_mean = biflow_bwd_eth_ipv4_data_len_std \
            = biflow_bwd_eth_ipv4_data_len_var = biflow_bwd_eth_ipv4_data_len_max = biflow_bwd_eth_ipv4_data_len_min = 0.0
        else:
            biflow_bwd_eth_ipv4_data_len_total = round(sum(biflow_bwd_eth_ipv4_data_lens), 3)
            biflow_bwd_eth_ipv4_data_len_mean = round(np.mean(biflow_bwd_eth_ipv4_data_lens), 3)
            biflow_bwd_eth_ipv4_data_len_std = round(np.std(biflow_bwd_eth_ipv4_data_lens), 3)
            biflow_bwd_eth_ipv4_data_len_var = round(np.var(biflow_bwd_eth_ipv4_data_lens), 3)
            biflow_bwd_eth_ipv4_data_len_max = round(max(biflow_bwd_eth_ipv4_data_lens), 3)
            biflow_bwd_eth_ipv4_data_len_min = round(min(biflow_bwd_eth_ipv4_data_lens), 3)

        # =============
        # TIME FEATURES
        # =============
        biflow_any_duration = round((biflow_any_last_packet_time - biflow_any_first_packet_time)/time_scale_factor, 3)
        biflow_any_first_packet_time = unixtime_to_datetime(biflow_any_first_packet_time)
        biflow_any_last_packet_time = unixtime_to_datetime(biflow_any_last_packet_time)
        if biflow_any_duration == 0:
            biflow_any_packets_per_sec = biflow_fwd_packets_per_sec = biflow_bwd_packets_per_sec = 0.0
            biflow_any_bytes_per_sec = biflow_fwd_bytes_per_sec = biflow_bwd_bytes_per_sec = 0.0
        else:
            biflow_any_packets_per_sec = round(biflow_any_n_packets/biflow_any_duration, 3)
            biflow_fwd_packets_per_sec = round(biflow_fwd_n_packets/biflow_any_duration, 3)
            biflow_bwd_packets_per_sec = round(biflow_bwd_n_packets/biflow_any_duration,3 )
            biflow_any_bytes_per_sec = round(biflow_any_eth_ipv4_data_len_total/biflow_any_duration, 3)
            biflow_fwd_bytes_per_sec = round(biflow_fwd_eth_ipv4_data_len_total/biflow_any_duration, 3)
            biflow_bwd_bytes_per_sec = round(biflow_bwd_eth_ipv4_data_len_total/biflow_any_duration, 3)

        # =========================================================================
        # Packet Header Lengths (14 byte Ether header + ip header + tcp/udp header)
        # =========================================================================

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
            biflow_bwd_eth_ipv4_header_len_total = biflow_bwd_eth_ipv4_header_len_mean = biflow_bwd_eth_ipv4_header_len_std \
            = biflow_bwd_eth_ipv4_header_len_var = biflow_bwd_eth_ipv4_header_len_max = biflow_bwd_eth_ipv4_header_len_min = 0.0
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
            biflow_any_iat_total = biflow_any_iat_mean = biflow_any_iat_std = biflow_any_iat_var = biflow_any_iat_max = biflow_any_iat_min = 0.0
        else:
            biflow_any_iat_total = round(sum(biflow_any_iats), 3)
            biflow_any_iat_mean = round(np.mean(biflow_any_iats), 3)
            biflow_any_iat_std = round(np.std(biflow_any_iats), 3)
            biflow_any_iat_var = round(np.var(biflow_any_iats), 3)
            biflow_any_iat_max = round(max(biflow_any_iats), 3)
            biflow_any_iat_min = round(min(biflow_any_iats), 3)

        # Packet IATs need at least 2 packets to be properly populated
        if len(biflow_fwd_iats) == 0:
            biflow_fwd_iat_total = biflow_fwd_iat_mean = biflow_fwd_iat_std = biflow_fwd_iat_var =biflow_fwd_iat_max = biflow_fwd_iat_min = 0.0
        else:
            biflow_fwd_iat_total = round(sum(biflow_fwd_iats), 3)
            biflow_fwd_iat_mean = round(np.mean(biflow_fwd_iats), 3)
            biflow_fwd_iat_std = round(np.std(biflow_fwd_iats), 3)
            biflow_fwd_iat_var = round(np.var(biflow_fwd_iats), 3)
            biflow_fwd_iat_max = round(max(biflow_fwd_iats), 3)
            biflow_fwd_iat_min = round(min(biflow_fwd_iats), 3)

        # ======================
        # IP Fragmentation Flags
        # ======================
        biflow_any_eth_ipv4_df_flags_total = round(sum(biflow_any_eth_ipv4_df_flags), 3)
        biflow_any_eth_ipv4_df_flags_mean = round(np.mean(biflow_any_eth_ipv4_df_flags), 3)
        biflow_any_eth_ipv4_df_flags_std = round(np.std(biflow_any_eth_ipv4_df_flags), 3)
        biflow_any_eth_ipv4_df_flags_var = round(np.var(biflow_any_eth_ipv4_df_flags), 3)
        biflow_any_eth_ipv4_df_flags_max = round(max(biflow_any_eth_ipv4_df_flags), 3)
        biflow_any_eth_ipv4_df_flags_min = round(min(biflow_any_eth_ipv4_df_flags), 3)

        biflow_fwd_eth_ipv4_df_flags_total = round(sum(biflow_fwd_eth_ipv4_df_flags), 3)
        biflow_fwd_eth_ipv4_df_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_df_flags), 3)
        biflow_fwd_eth_ipv4_df_flags_std = round(np.std(biflow_fwd_eth_ipv4_df_flags), 3)
        biflow_fwd_eth_ipv4_df_flags_var = round(np.var(biflow_fwd_eth_ipv4_df_flags), 3)
        biflow_fwd_eth_ipv4_df_flags_max = round(max(biflow_fwd_eth_ipv4_df_flags), 3)
        biflow_fwd_eth_ipv4_df_flags_min = round(min(biflow_fwd_eth_ipv4_df_flags), 3)

        biflow_bwd_eth_ipv4_df_flags_total = round(sum(biflow_bwd_eth_ipv4_df_flags), 3)
        biflow_bwd_eth_ipv4_df_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_df_flags), 3)
        biflow_bwd_eth_ipv4_df_flags_std = round(np.std(biflow_bwd_eth_ipv4_df_flags), 3)
        biflow_bwd_eth_ipv4_df_flags_var = round(np.var(biflow_bwd_eth_ipv4_df_flags), 3)
        biflow_bwd_eth_ipv4_df_flags_max = round(max(biflow_bwd_eth_ipv4_df_flags), 3)
        biflow_bwd_eth_ipv4_df_flags_min = round(min(biflow_bwd_eth_ipv4_df_flags), 3)

        biflow_any_eth_ipv4_mf_flags_total = round(sum(biflow_any_eth_ipv4_mf_flags), 3)
        biflow_any_eth_ipv4_mf_flags_mean = round(np.mean(biflow_any_eth_ipv4_mf_flags), 3)
        biflow_any_eth_ipv4_mf_flags_std = round(np.std(biflow_any_eth_ipv4_mf_flags), 3)
        biflow_any_eth_ipv4_mf_flags_var = round(np.var(biflow_any_eth_ipv4_mf_flags), 3)
        biflow_any_eth_ipv4_mf_flags_max = round(max(biflow_any_eth_ipv4_mf_flags), 3)
        biflow_any_eth_ipv4_mf_flags_min = round(min(biflow_any_eth_ipv4_mf_flags), 3)

        biflow_fwd_eth_ipv4_mf_flags_total = round(sum(biflow_fwd_eth_ipv4_mf_flags), 3)
        biflow_fwd_eth_ipv4_mf_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_mf_flags), 3)
        biflow_fwd_eth_ipv4_mf_flags_std = round(np.std(biflow_fwd_eth_ipv4_mf_flags), 3)
        biflow_fwd_eth_ipv4_mf_flags_var = round(np.var(biflow_fwd_eth_ipv4_mf_flags), 3)
        biflow_fwd_eth_ipv4_mf_flags_max = round(max(biflow_fwd_eth_ipv4_mf_flags), 3)
        biflow_fwd_eth_ipv4_mf_flags_min = round(min(biflow_fwd_eth_ipv4_mf_flags), 3)

        biflow_bwd_eth_ipv4_mf_flags_total = round(sum(biflow_bwd_eth_ipv4_mf_flags), 3)
        biflow_bwd_eth_ipv4_mf_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_mf_flags), 3)
        biflow_bwd_eth_ipv4_mf_flags_std = round(np.std(biflow_bwd_eth_ipv4_mf_flags), 3)
        biflow_bwd_eth_ipv4_mf_flags_var = round(np.var(biflow_bwd_eth_ipv4_mf_flags), 3)
        biflow_bwd_eth_ipv4_mf_flags_max = round(max(biflow_bwd_eth_ipv4_mf_flags), 3)
        biflow_bwd_eth_ipv4_mf_flags_min = round(min(biflow_bwd_eth_ipv4_mf_flags), 3)

        # Packet IATs need at least 2 packets to be properly populated
        if len(biflow_bwd_iats) == 0:
            biflow_bwd_iat_total = biflow_bwd_iat_mean = biflow_bwd_iat_std = biflow_bwd_iat_var = biflow_bwd_iat_max = biflow_bwd_iat_min = 0.0
        else:
            biflow_bwd_iat_total = round(sum(biflow_bwd_iats), 3)
            biflow_bwd_iat_mean = round(np.mean(biflow_bwd_iats), 3)
            biflow_bwd_iat_std = round(np.std(biflow_bwd_iats), 3)
            biflow_bwd_iat_var = round(np.var(biflow_bwd_iats), 3)
            biflow_bwd_iat_max = round(max(biflow_bwd_iats), 3)
            biflow_bwd_iat_min = round(min(biflow_bwd_iats), 3)

        # ===============
        # WRAP-UP RESULTS
        # ===============
        biflow_local_vars = locals()
        biflow_gene_values_list = [biflow_local_vars[var_name] for var_name in ipv4_biflow_genes_header_list]
        biflow_genes_generator = dict(zip(ipv4_biflow_genes_header_list, biflow_gene_values_list))

        yield biflow_genes_generator

def output_biflow_genes(ipv4_flow_genes_generator, output_type, output_dir=False, over_ipv4=False):
    """
    Output all flows and their genes with the following supported protocols, where important in:
        - L1: Ethernet
        - L2: Ethernet
        - L3: IPv4
        - L4: UDP, TCP
    """
    if output_type=="csv":
        ipv4_flow_genes_header_str = get_biflow_header_by_type("ipv4")
        ipv4_flow_genes_csv = ipv4_flow_genes_header_str + "\n"
        for ipv4_flow_genes_dict in ipv4_flow_genes_generator:
            ipv4_flow_genes_list = list(ipv4_flow_genes_dict.values())
            ipv4_flow_genes_csv += generate_flow_line(ipv4_flow_genes_list) + "\n"
        f = open(output_dir + os.sep + "ipv4-biflows2.csv", "w")
        f.write(ipv4_flow_genes_csv)
        f.close()

def generate_network_objets(input_pcap_file, args, netmeter_globals):
    """
    Build all network objects: packets, flows, talkers and hosts
    """
    if args.verbose:
        run_init_time = time.time()
        print(make_header_string("1. Network Object Construction", separator="=", big_header=True), flush=True)

    # =======
    # Packets
    # =======
    packet_genes = build_packets(input_pcap_file, args)

    # ====================
    # Unidirectional Flows
    # ====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("1.2. Layer-3 Unidirectional Flows: IPv4"), flush=True)

    l3_uniflows, l3_uniflow_ids = build_l3_uniflows(packet_genes)
    del(packet_genes)

    if args.verbose:
        n_preserved_packets = sum([len(l3_uniflows[l3_uniflow_id]) for l3_uniflow_id in l3_uniflow_ids])
        print("[+] Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] Flows detected:" + cterminal.colors.GREEN, len(l3_uniflow_ids), "IPv4 UniFlows" + cterminal.colors.ENDC, flush=True)
        print("[+] Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # ===================
    # Bidirectional Flows
    # ===================

    # -------
    # Layer 3
    # -------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("1.3. Layer-3 Bidirectional Flows: IPv4"), flush=True)

    l3_biflows, l3_biflow_ids = build_l3_biflows(l3_uniflows, l3_uniflow_ids)
    del(l3_uniflows)
    del(l3_uniflow_ids)

    if args.verbose:
        n_preserved_packets = sum([len(l3_biflows[l3_biflow_id]) for l3_biflow_id in l3_biflow_ids])
        print("[+] IPv4 Packets preserved:", n_preserved_packets, "IPv4 Packets", flush=True)
        print("[+] IPv4 BiFlows detected:" + cterminal.colors.GREEN, len(l3_biflows), "IPv4 BiFlows" + cterminal.colors.ENDC, flush=True)
        print("[+] Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # -------
    # Layer 4
    # -------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("1.4. Layer-4 Bidirectional Flows: UDP and TCP"), flush=True)

    udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids = build_l4_biflows(l3_biflows, l3_biflow_ids)
    
    if args.verbose:
        n_preserved_udp_packets = sum([len(udp_biflows[udp_biflow_id]) for udp_biflow_id in udp_biflow_ids])
        n_preserved_tcp_packets = sum([len(tcp_biflows[tcp_biflow_id]) for tcp_biflow_id in tcp_biflow_ids])

        print("[+] IPv4-UDP Packets preserved:", n_preserved_udp_packets, "IPv4-UDP Packets", flush=True)
        print("[+] IPv4-TCP Packets preserved:", n_preserved_tcp_packets, "IPv4-TCP Packets", flush=True)
        print("[+] IPv4-UDP Flows detected:" + cterminal.colors.GREEN, len(udp_biflows), "IPv4-UDP BiFlows" + cterminal.colors.ENDC, flush=True)
        print("[+] IPv4-TCP Flows detected:" + cterminal.colors.GREEN, len(tcp_biflows), "IPv4-TCP BiFlows" + cterminal.colors.ENDC, flush=True)
        print("[+] Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # =================
    # IPv4 BiFlow Genes
    # =================
    if args.verbose:
        print(make_header_string("2. Layer-3 and Layer-4 Bidirectional Flow Genes", separator="=", big_header=True), flush=True)
    # ------------------------------
    # IPv4 Flow Feature Calculations
    # ------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("2.1. IPv4 & (TCP|UDP) BiFlow Genes"), flush=True)

    # TODO: use the udp and tcp biflows as input for calculate_l3_l4_biflow_genes function and calculate specific l4 flow genes
    # (merge TCP, think UDP/TCP)
    l3_l4_flow_genes_generator = calculate_l3_l4_biflow_genes(tcp_biflows, tcp_biflow_ids)

    if args.verbose:
        l3_n_flow_genes = get_biflow_header_by_type("ipv4").count("|") - 2
        print("[+] Calculated IPv4 & (TCP|UDP) BiFlow Genes:" + cterminal.colors.GREEN,
            l3_n_flow_genes, "BiFlow Genes" + cterminal.colors.ENDC, flush=True)
        print("[+] Calculated in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True)

    # ------------------------
    # IPv4 Flow Feature Output
    # ------------------------
    if args.verbose:
        module_init_time = time.time()

    output_biflow_genes(l3_l4_flow_genes_generator, args.output_type, netmeter_globals.csv_output_dir)

    if args.verbose:
        print("[+] Saved in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # ========
    # FINISHED
    # ========
    if args.verbose:
        print(make_header_string("Total Extraction Time", separator="=", big_header=True), flush=True)
        print("[+] Script took" + cterminal.colors.YELLOW, round(time.time() - run_init_time, 3), "seconds" + cterminal.colors.ENDC, "to complete", flush=True)

def run():
    args = NetMeterArgs().args
    netmeter_globals = NetMeterGlobals(args)
    
    os.makedirs(netmeter_globals.pcap_files_dir, exist_ok=True)
    os.makedirs(netmeter_globals.csv_files_dir, exist_ok=True)

    print(make_header_string("INPUT/OUTPUT INFORMATION", separator="+", big_header=True), flush=True)
    print("[+] Input PCAP file:"  + cterminal.colors.BLUE, args.pcap_path + cterminal.colors.ENDC, flush=True)
    pcap_size_bytes = os.path.getsize(args.pcap_path)
    pcap_size_str = (str(round(pcap_size_bytes/(1024**2), 3)) + " megabytes") if (pcap_size_bytes < 1024**3) \
        else (str(round(pcap_size_bytes/(1024**3), 3)) + " gigabytes")

    print("[+] Parsing and working on", cterminal.colors.BLUE + pcap_size_str + cterminal.colors.ENDC, "of data. Please wait.", flush=True)

    if args.output_type=="csv":
        os.makedirs(netmeter_globals.csv_output_dir, exist_ok=True)
        print("[+] Output CSV file:", cterminal.colors.BLUE + netmeter_globals.csv_output_dir + cterminal.colors.ENDC, flush=True)

    if args.verbose:
        print("")
        print(make_header_string("VERBOSE OUTPUT ACTIVATED", separator="+", big_header=True), flush=True)
        print(make_header_string("NetMeter Supported Protocols for NetGene Extraction", separator="-", big_header=True), flush=True)
        print("[+] Layer 1: Ethernet", flush=True)
        print("[+] Layer 2: Ethernet", flush=True)
        print("[+] Layer 3: IPv4", flush=True)
        print("[-] Layer 3+: ICMPv4, IGMPv4", flush=True)
        print("[+] Layer 4: TCP, UDP", flush=True, end="\n\n")

    with open(args.pcap_path, "rb") as input_pcap_file:
        generate_network_objets(input_pcap_file, args, netmeter_globals)

# Reading Command-Line Output:
# [!]: Error Information
# [+]: Normal Information
if __name__ == "__main__":
    run()
