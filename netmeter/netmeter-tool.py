#!/usr/bin/env python3

"""
This script is meant to output "hosts" (ipX), "talkers" (ipX-ipY) and "flows"
(ipX-portA-ipY-portB-protocol_stack-inner_sep_counter) and their respective
conceptual and statistical features to build a dataset. It's one of the three
main tasks of my thesis.

AUTHORSHIP:
Joao Meira <joao.meira.cs@gmail.com>

"""

# ===============================================================
# OSI-layer protocols: https://en.wikipedia.org/wiki/List_of_network_protocols_(OSI_model)
# L0 (physical methods of propagation): Copper, Fiber, Wireless
# NetMeter Protocols
# L1-protocols: Ethernet (Physical Layer)
# L2-protocols: **Ethernet**, ??MAC+ARP??
# https://en.wikipedia.org/wiki/EtherType; https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
# L3-protocols: **IPv4 (IP-4)**, IPv6 (IP-41)
# L3plus-protocols: ??ICMPv4 (IP-1)??, ICMPv6 (IP-58), GRE (IP-47)
# L4-protocols: **TCP (IP-6)**, ??UDP (IP-17)??
# ===============================================================

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

try:
    this_script_dirpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, this_script_dirpath + os.sep + "auxiliary-python-modules")
    import cterminal
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")


# ===============
# ARGUMENT PARSER
# ===============

oparser = argparse.ArgumentParser(prog="NetMeter", description="Network-based feature extraction tool")
oparser.add_argument("pcap_path", metavar="pcap_path", help="Input PCAP file")
#oparser.add_argument("-l", "--flow-label", help="label all flows as X", dest="flow_label", default="unknown")
oparser.add_argument("-D", "--data-dir", help="Data directory", dest="data_dir", default="data-files")
oparser.add_argument("-T", "--output-type", help="Output type: mongo, csv, ...", dest="output_type", type=str.lower, default="csv")
oparser.add_argument("-s", "--safe-check", action="store_true", help="Perform safe checks", dest="safe_check")
oparser.add_argument("-d", "--debug", action="store_true", help="Debug output", dest="debug")
oparser.add_argument("-v", "--verbose", action="store_true", help="Verbose output", dest="verbose")
args = oparser.parse_args()

# ==================
# VALIDATE ARGUMENTS
# ==================

"""
args_list = [args.register != "", args.login != "",\
            args.listindividualfiles, args.sendindividualfiles != "", args.fetchindividualfiles != "", args.deleteindividualfiles != "",\
            args.listallusers, args.share != "", args.fetchshared != "", args.sendshared != "",\
            args.listmybackups, args.revert, args.revertshared]

if True not in args_list:
    print "[!][" + now() + "] You need to choose an option."
    oparser.print_help()
    exit()
"""
pcap_files_dir = args.data_dir + os.sep + "pcap"
csv_files_dir = args.data_dir + os.sep + "csv"
os.makedirs(pcap_files_dir, exist_ok=True)
os.makedirs(csv_files_dir, exist_ok=True)
# csv output dir is only created when needed
csv_output_dir = csv_files_dir + os.sep + os.path.splitext(os.path.basename(args.pcap_path))[0]

# ==========================
# START: Auxiliary Functions
# ==========================

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def flow_id_to_talker_id(flow_id):
    splitted_flow_id = flow_id.split("-")
    return splitted_flow_id[0] + "-" + splitted_flow_id[2]

def generate_flow_line(flow_features):
    return flow_id_to_str(flow_features[0]) + "|" + "|".join(map(str,flow_features[1:]))

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

# BIG-TODO: Need to improve my previous code because a lot of code is reusable, and a lot of code is just hardcoded.
def build_packets(file):
    """
    Process PCAP and build packets
    """

    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("NETWORK PACKETS"), flush=True)
    file.seek(0)
    pcap = dpkt.pcap.Reader(file)
    n_packets_ipv4 = 0
    n_packets_ipv4_tcp = 0
    n_packets_ipv4_udp = 0
    n_packets_ipv4_icmp = 0
    n_packets_ipv4_others = 0
    n_packets_others = 0

    # supported protocols above IPv4
    supported_l3plus_protocols = ("ICMP")
    supported_l4_protocols = ("TCP", "UDP")

    # TODO: https://dpkt.readthedocs.io/en/latest/print_icmp.html
    # TODO: find a database and dataset format which accomodates such diverse feature formats (tcp vs udp vs icmp) while maintaining
    # all the relevant features for each format... maybe there needs to be dataset separation, or maybe it's enough to put a "L3-protocol"
    # and "L4-protocol" field to separate those formats in the same dataset and zero-out different values
    packets = []
    
    # [+] PARSE ALL PACKETS
    for timestamp, buf in pcap:
        # =======================
        # LAYER1/LAYER2: ETHERNET
        # =======================
        # FUTURE-TODO: implement handlers for other L1/L2 protocols

        frame_len = len(buf)

        # Unpack the Ethernet frame (mac src, mac dst, ether type). Buf must be of the expected format: L1 Ethernet and L2 Ethernet.
        eth = dpkt.ethernet.Ethernet(buf)

        # ============
        # LAYER3: IPv4
        # ============
        # FUTURE-TODO: implement handlers for other L3 protocols

        # Check if the Ethernet data contains an IPv4 packet. If it doesn't, ignore it.
        if not isinstance(eth.data, dpkt.ip.IP):
            n_packets_others += 1
            continue

        # Unpack the data within the Ethernet frame: the confirmed IPv4 packet
        ip = eth.data

        # =========================
        # IPv4-only packet features
        # =========================
        #https://en.wikipedia.org/wiki/IPv4

        # Source and destination IP
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)

        # IP lengths
        ipv4_options_len = len(ip.opts)
        ipv4_header_len = ip.__hdr_len__ + ipv4_options_len
        ipv4_data_len = len(ip.data)

        # Fragment information
        ipv4_df_flag = int(ip.off & dpkt.ip.IP_DF)
        ipv4_mf_flag = int(ip.off & dpkt.ip.IP_MF)

        # Unpack the data within the IPv4 frame: any protocol which acts above IPv4, even in the same layer
        transport_layer = ip.data

        # Extracting layer 4 (transport) protocol name, in case it exists
        transport_protocol_name = type(transport_layer).__name__

        if transport_protocol_name in supported_l3plus_protocols:
            if transport_protocol_name == "ICMP":
                n_packets_ipv4_icmp += 1
            else:
                n_packets_ipv4_others += 1
        elif transport_protocol_name in supported_l4_protocols:
            n_packets_ipv4 += 1
            # ==================
            # L4 packet features
            # ==================
            src_port = transport_layer.sport
            dst_port = transport_layer.dport

            # check if this transport protocol has options and use it
            transport_options_len = len(transport_layer.opts) if hasattr(transport_layer, "opts") else 0
            transport_header_len = transport_layer.__hdr_len__
            transport_data_len = len(transport_layer.data)

            if args.debug:
                print(make_header_string("SINGLE PACKETS INFO"), flush=True)
                print("Packet no.:", n_packets_ipv4 + n_packets_others, flush=True)
                print("IPv4 header length:", ipv4_header_len, flush=True)
                print("IPv4 options length:", ipv4_options_len, flush=True)
                print("IPv4 data length:", ipv4_data_len, flush=True)
                print("Transport header length:", transport_header_len, flush=True)
                print("Transport options length:", transport_options_len, flush=True)
                print("Transport data length:", transport_data_len, flush=True)

            # 6-tuple: src ip, src port, dst ip, dst port, protocol_stack, inner_sep_counter
            # note: inner_sep_counter is incremented whenever a flow reaches its end,
            # independently of the protocol used
            flow_id = (src_ip, src_port, dst_ip, dst_port, transport_protocol_name, 0)
            ipv4_packet_features = [flow_id, str(datetime.datetime.utcfromtimestamp(timestamp)), ipv4_header_len, ipv4_data_len, ipv4_df_flag, ipv4_mf_flag]
            packet_features = ipv4_packet_features
            if transport_protocol_name == "TCP":
                n_packets_ipv4_tcp += 1
                # ===================
                # TCP packet features
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
                #tcp_packet_features = [tcp_fin_flag, tcp_syn_flag, tcp_rst_flag, tcp_psh_flag, tcp_ack_flag, tcp_urg_flag, tcp_ece_flag, tcp_cwr_flag]
                #packet_features += tcp_packet_features
                packets.append(packet_features)
            elif transport_protocol_name == "UDP":
                n_packets_ipv4_udp += 1
                # ===================
                # UDP packet features
                # ===================
                # TODO: in case it applies, do udp packet features
                #udp_packet_features = []
                #packet_features += udp_packet_features
            
        else:
            n_packets_ipv4_others += 1

    if args.verbose:
        print("Number of IPv4 packets:", n_packets_ipv4, "packets", flush=True)
        print("Number of IPv4-TCP packets:", n_packets_ipv4_tcp, "packets", flush=True)
        print("Number of IPv4-UDP packets:", n_packets_ipv4_udp, "packets", flush=True)
        print("Number of IPv4-ICMP packets:", n_packets_ipv4_icmp, "packets", flush=True)
        print("Number of IPv4-<Other> packets:", n_packets_ipv4_others, "packets", flush=True)
        print("Number of <Other> packets:", n_packets_others, "packets", flush=True)
        print("Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")
    # Verify some safe conditions
    if args.safe_check:
        packet_no = n_packets_ipv4 + n_packets_others
        if ipv4_header_len < 20 or ipv4_header_len > 60:
            raise ValueError("Invalid IPv4 header length in packet no.", packet_no)

    return packets

def build_uniflows(packets):
    """Associate uniflow_ids to packets"""
    uniflows = dict()
    uniflow_ids = list()
    for packet in packets:
        flow_id = packet[0]
        uniflow_ids.append(flow_id)
        try:
            uniflows[flow_id].append(packet)
        except KeyError:
            uniflows[flow_id] = [packet]
    #remove duplicates mantaining order
    uniflow_ids = list(OrderedDict.fromkeys(uniflow_ids))
    return uniflows, uniflow_ids

def get_unique_matching_uniflow_ids(uniflow_ids):
    """Return matching unidirectional flow ids, with fwd_flow_id as key and bwd_flow_id as value, and not vice-versa"""
    matching_uniflow_ids_dict = dict()
    fwd_flow_ids = list()
    for uniflow_id in uniflow_ids:
        reversed_uniflow_id = (uniflow_id[2],uniflow_id[3],uniflow_id[0],uniflow_id[1],uniflow_id[4],uniflow_id[5])
        if reversed_uniflow_id in uniflow_ids:
            if reversed_uniflow_id not in matching_uniflow_ids_dict:
                fwd_flow_ids.append(uniflow_id)
                matching_uniflow_ids_dict[uniflow_id] = reversed_uniflow_id
        else:
            if reversed_uniflow_id not in matching_uniflow_ids_dict:
                fwd_flow_ids.append(uniflow_id)
                matching_uniflow_ids_dict[uniflow_id] = False

    return matching_uniflow_ids_dict, fwd_flow_ids

def build_biflows(uniflows, uniflow_ids):
    """Join unidirectional flow information into its bidirectional flow equivalent"""
    matching_uniflow_ids_dict, fwd_flow_ids = get_unique_matching_uniflow_ids(uniflow_ids)
    flows = dict()
    flow_ids = list()

    for fwd_flow_id in fwd_flow_ids:
        # have in mind every uniflow_id in this list will have been constituted by the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet, hence uniflow_id = fwd_flow_id
        bwd_flow_id = matching_uniflow_ids_dict[fwd_flow_id]
        flow_ids.append(fwd_flow_id)
        if bwd_flow_id:
            flows[fwd_flow_id] = uniflows[fwd_flow_id] + uniflows[bwd_flow_id]
        else:
            flows[fwd_flow_id] = uniflows[fwd_flow_id]
    return flows, flow_ids

def build_tcp_flows(flows, flow_ids):
    """Separate bidirectional flows using TCP's RFC rules"""
    # FUTURE-TODO: validate using tcp_seq
    # fin,syn,rst,psh,ack,urg,ece,cwr (2,...,9)
    tcp_flows = dict()
    # ordered flow keys (by flow start time)
    tcp_flow_ids = []

    # create conventionally correct flows
    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        curr_flow.sort(key=lambda x: x[1])       # sorting the packets in each flow by date-and-time
        flow_any_n_packets = len(curr_flow)

        if flow_any_n_packets == 0:
            raise ValueError("A flow can't have 0 packets.")
        elif flow_any_n_packets in (1,2,3):     #1/2/3 pacotes num so flow_id perfazem no maximo 1 e 1 so tcp flow
            tcp_flows[flow_id] = curr_flow
            tcp_flow_ids.append(flow_id)
        else:
            curr_packet_index = 0
            previous_packet_index = 0
            flow_begin = False
            inner_sep_counter = 0
            while curr_packet_index < flow_any_n_packets:
                fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1 = curr_flow[curr_packet_index][-8:]
                if curr_packet_index == flow_any_n_packets-2:   # penultimate packet
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = curr_flow[curr_packet_index+1][-8:]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3 = [False]*8
                elif curr_packet_index == flow_any_n_packets-1: # last packet
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = [False]*8
                    fin3,syn3,rst3,psh3,ack3,urg2,ece3,cwr3 = [False]*8
                else:               # other packets
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = curr_flow[curr_packet_index+1][-8:]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3 = curr_flow[curr_packet_index+2][-8:]

                # =========================
                # TCP FLOW INITIATION RULES
                # =========================
                # r1,r2: begin flow
                r1 = (syn1 and not ack1) and (syn2 and ack2) and ack3           # 3-way handshake (full-duplex), syn+syn-ack+ack / syn+syn-ack+syn-ack
                r2 = (syn1 and not ack1) and ack2                               # 2-way handshake (half-duplex), syn+syn-ack / syn+ack

                # ==========================
                # TCP FLOW TERMINATION RULES
                # ==========================
                # r3,r4: end flow
                r3 = fin1 and (fin2 and ack2) and ack3                          # graceful termination
                r4 = rst1 and not rst2                                          # abort termination

                # ===================
                # TCP FLOW INITIATION
                # ===================
                # consider flow begin or ignore it (considering it is safer, but not considering it will leave out flows that have started before the capture)
                # the only rule used for flow begin will be the half-duplex handshake rule because it is inclusive of the full-duplex handshake rule,
                # i.e., (r2 or r1) == r2, for any flow
                if r2:
                    flow_begin = True

                # we consider flows only the ones that start with a 2 or 3-way handshake (r1,r2)
                # the flow end conditions are r3 and r4, (fin,fin-ack,ack)/(rst,!rst,---), or if the packet is the last one of the existing communication
                if flow_begin:
                    tcp_flow_id = (flow_id[0], flow_id[1], flow_id[2], flow_id[3], flow_id[4], flow_id[5] + inner_sep_counter)
                    next_packet_index = 0
                    # ====================
                    # TCP FLOW TERMINATION
                    # ====================
                    # graceful termination
                    if r3:
                        tcp_flows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+3]
                        tcp_flow_ids.append(tcp_flow_id)
                        flow_begin = False
                        previous_packet_index = curr_packet_index + 3
                        inner_sep_counter += 1
                        flow_tcp_termination_graceful = True
                    else:
                        # abort termination
                        if r4:
                            tcp_flows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                            tcp_flow_ids.append(tcp_flow_id)
                            flow_begin = False
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                            flow_tcp_termination_abort = True
                        # null termination
                        elif curr_packet_index == flow_any_n_packets-1:
                            tcp_flows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
                            tcp_flow_ids.append(tcp_flow_id)
                            flow_begin = False
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                            flow_tcp_termination_null = True
                # keep iterating through the packets
                curr_packet_index+=1
    return tcp_flows,tcp_flow_ids

def get_flow_header_by_type(protocol_stack):
    features_dir = "network-objects" + os.sep + "features"
    features_header_str = ""
    if protocol_stack == "ipv4":
        features_file = features_dir + os.sep + "ipv4-flow-header.txt"
    else:
        raise ValueError("Protocol stack \"" + protocol_stack + "\" not supported. Supported protocol stacks: ipv4")

    f = open(features_file, "r")
    features_header_str = f.read().replace("\n", "|")
    f.close()

    return features_header_str

def calculate_ipv4_flow_features(flows, flow_ids):
    """Calculate and output IPv4 flow features"""
    time_scale_factor = 1000.0
    ipv4_flow_features_header_str = get_flow_header_by_type("ipv4")
    ipv4_flow_features_header_list = ipv4_flow_features_header_str.split("|")

    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        # DEV-NOTE: curr_flow[packet_index][packet_feature_index]
        # NOTE: backward packets may not exist

        # =========================
        # PREPARE DATA STRUCTURES |
        # =========================

        # ======================
        # Packet Number Features
        # ======================
        flow_any_n_packets = len(curr_flow)
        flow_fwd_n_packets = 0
        flow_bwd_n_packets = 0

        flow_any_n_data_packets = 0
        flow_fwd_n_data_packets = 0
        flow_bwd_n_data_packets = 0

        # =============
        # Time Features
        # =============
        flow_any_iats = list()
        flow_fwd_iats = list()
        flow_bwd_iats = list()

        # ===============
        # Length Features
        # ===============
        flow_any_ipv4_data_lens = list()
        flow_fwd_ipv4_data_lens = list()
        flow_bwd_ipv4_data_lens = list()

        flow_any_ipv4_header_lens = list()
        flow_fwd_ipv4_header_lens = list()
        flow_bwd_ipv4_header_lens = list()

        # ======================
        # IP Fragmentation Flags
        # ======================
        flow_any_df_flags = list()
        flow_fwd_df_flags = list()
        flow_bwd_df_flags = list()

        flow_any_mf_flags = list()
        flow_fwd_mf_flags = list()
        flow_bwd_mf_flags = list()

        # ==========================
        # POPULATE DATA STRUCTURES |
        # ==========================
        curr_packet_index = 0
        while curr_packet_index < flow_any_n_packets:
            previous_packet = curr_flow[curr_packet_index-1]
            previous_packet_flow_id = previous_packet[0]
            previous_packet_timestamp = previous_packet[1]

            curr_packet = curr_flow[curr_packet_index]
            curr_packet_flow_id = curr_packet[0]
            curr_packet_timestamp = curr_packet[1]
            curr_packet_ipv4_header_len = curr_packet[2]
            curr_packet_ipv4_data_len = curr_packet[3]
            curr_packet_df_flag = curr_packet[4]
            curr_packet_mf_flag = curr_packet[5]

            # IAT requires that there's at least two packets.
            if curr_packet_index >= 1:
                curr_packet_time = datetime_to_unixtime(previous_packet_timestamp)
                next_packet_time = datetime_to_unixtime(curr_packet_timestamp)
                curr_packet_iat = (next_packet_time - curr_packet_time)/time_scale_factor
                flow_any_iats.append(curr_packet_iat)
                if previous_packet_flow_id == flow_id:
                    flow_fwd_iats.append(curr_packet_iat)
                else:
                    flow_bwd_iats.append(curr_packet_iat)

            flow_any_ipv4_data_lens.append(curr_packet_ipv4_data_len)
            flow_any_ipv4_header_lens.append(curr_packet_ipv4_header_len)
            flow_any_df_flags.append(curr_packet_df_flag)
            flow_any_mf_flags.append(curr_packet_mf_flag)

            if curr_packet_flow_id == flow_id:
                flow_fwd_ipv4_data_lens.append(curr_packet_ipv4_data_len)
                flow_fwd_ipv4_header_lens.append(curr_packet_ipv4_header_len)
                flow_fwd_df_flags.append(curr_packet_df_flag)
                flow_fwd_mf_flags.append(curr_packet_mf_flag)

                flow_fwd_n_packets += 1
                if curr_packet_ipv4_header_len != curr_packet_ipv4_data_len:
                    flow_any_n_data_packets += 1
                    flow_fwd_n_data_packets += 1
            else:
                flow_bwd_ipv4_data_lens.append(curr_packet_ipv4_data_len)
                flow_bwd_ipv4_header_lens.append(curr_packet_ipv4_header_len)
                flow_bwd_df_flags.append(curr_packet_df_flag)
                flow_bwd_mf_flags.append(curr_packet_mf_flag)

                flow_bwd_n_packets += 1
                if curr_packet_ipv4_header_len != curr_packet_ipv4_data_len:
                    flow_any_n_data_packets += 1
                    flow_bwd_n_data_packets += 1

            curr_packet_index+=1

        # ================================
        # ENRICH AND EXTRACT INFORMATION |
        # ================================

        # ======================
        # ADDITIONAL INFORMATION
        # ======================
        first_packet = curr_flow[0]
        last_packet = curr_flow[flow_any_n_packets-1]
        first_packet_timestamp = first_packet[1]
        last_packet_timestamp = last_packet[1]

        flow_any_first_packet_time = datetime_to_unixtime(first_packet_timestamp)
        flow_any_last_packet_time = datetime_to_unixtime(last_packet_timestamp)

        # ==============
        # Packet Lengths
        # ==============
        flow_any_ipv4_data_len_total = float(np.sum(flow_any_ipv4_data_lens))
        flow_any_ipv4_data_len_mean = float(np.mean(flow_any_ipv4_data_lens))
        flow_any_ipv4_data_len_std = float(np.std(flow_any_ipv4_data_lens))
        flow_any_ipv4_data_len_var = float(np.var(flow_any_ipv4_data_lens))
        flow_any_ipv4_data_len_max = float(np.max(flow_any_ipv4_data_lens))
        flow_any_ipv4_data_len_min = float(np.min(flow_any_ipv4_data_lens))

        flow_fwd_ipv4_data_len_total = float(np.sum(flow_fwd_ipv4_data_lens))
        flow_fwd_ipv4_data_len_mean = float(np.mean(flow_fwd_ipv4_data_lens))
        flow_fwd_ipv4_data_len_std = float(np.std(flow_fwd_ipv4_data_lens))
        flow_fwd_ipv4_data_len_var = float(np.var(flow_fwd_ipv4_data_lens))
        flow_fwd_ipv4_data_len_max = float(np.max(flow_fwd_ipv4_data_lens))
        flow_fwd_ipv4_data_len_min = float(np.min(flow_fwd_ipv4_data_lens))

        if len(flow_bwd_ipv4_data_lens) == 0:
            flow_bwd_ipv4_data_len_total = flow_bwd_ipv4_data_len_mean = flow_bwd_ipv4_data_len_std \
            = flow_bwd_ipv4_data_len_var = flow_bwd_ipv4_data_len_max = flow_bwd_ipv4_data_len_min = 0.0
        else:
            flow_bwd_ipv4_data_len_total = float(np.sum(flow_bwd_ipv4_data_lens))
            flow_bwd_ipv4_data_len_mean = float(np.mean(flow_bwd_ipv4_data_lens))
            flow_bwd_ipv4_data_len_std = float(np.std(flow_bwd_ipv4_data_lens))
            flow_bwd_ipv4_data_len_var = float(np.var(flow_bwd_ipv4_data_lens))
            flow_bwd_ipv4_data_len_max = float(np.max(flow_bwd_ipv4_data_lens))
            flow_bwd_ipv4_data_len_min = float(np.min(flow_bwd_ipv4_data_lens))

        # =============
        # TIME FEATURES
        # =============
        flow_any_duration = (flow_any_last_packet_time - flow_any_first_packet_time)/time_scale_factor
        flow_any_first_packet_time = unixtime_to_datetime(flow_any_first_packet_time)
        flow_any_last_packet_time = unixtime_to_datetime(flow_any_last_packet_time)
        if flow_any_duration == 0:
            flow_any_packets_per_sec = flow_fwd_packets_per_sec = flow_bwd_packets_per_sec = 0.0
            flow_any_bytes_per_sec = flow_fwd_bytes_per_sec = flow_bwd_bytes_per_sec = 0.0
        else:
            flow_any_packets_per_sec = float(flow_any_n_packets/flow_any_duration)
            flow_fwd_packets_per_sec = float(flow_fwd_n_packets/flow_any_duration)
            flow_bwd_packets_per_sec = float(flow_bwd_n_packets/flow_any_duration)
            flow_any_bytes_per_sec = float(flow_any_ipv4_data_len_total/flow_any_duration)
            flow_fwd_bytes_per_sec = float(flow_fwd_ipv4_data_len_total/flow_any_duration)
            flow_bwd_bytes_per_sec = float(flow_bwd_ipv4_data_len_total/flow_any_duration)

        # =========================================================================
        # Packet Header Lengths (14 byte Ether header + ip header + tcp/udp header)
        # =========================================================================

        flow_any_ipv4_header_len_total = float(np.sum(flow_any_ipv4_header_lens))
        flow_any_ipv4_header_len_mean = float(np.mean(flow_any_ipv4_header_lens))
        flow_any_ipv4_header_len_std = float(np.std(flow_any_ipv4_header_lens))
        flow_any_ipv4_header_len_var = float(np.var(flow_any_ipv4_header_lens))
        flow_any_ipv4_header_len_max = float(np.max(flow_any_ipv4_header_lens))
        flow_any_ipv4_header_len_min = float(np.min(flow_any_ipv4_header_lens))

        flow_fwd_ipv4_header_len_total = float(np.sum(flow_fwd_ipv4_header_lens))
        flow_fwd_ipv4_header_len_mean = float(np.mean(flow_fwd_ipv4_header_lens))
        flow_fwd_ipv4_header_len_std = float(np.std(flow_fwd_ipv4_header_lens))
        flow_fwd_ipv4_header_len_var = float(np.var(flow_fwd_ipv4_header_lens))
        flow_fwd_ipv4_header_len_max = float(np.max(flow_fwd_ipv4_header_lens))
        flow_fwd_ipv4_header_len_min = float(np.min(flow_fwd_ipv4_header_lens))

        if len(flow_bwd_ipv4_header_lens) == 0:
            flow_bwd_ipv4_header_len_total = flow_bwd_ipv4_header_len_mean = flow_bwd_ipv4_header_len_std \
            = flow_bwd_ipv4_header_len_var = flow_bwd_ipv4_header_len_max = flow_bwd_ipv4_header_len_min = 0.0
        else:
            flow_bwd_ipv4_header_len_total = float(np.sum(flow_bwd_ipv4_header_lens))
            flow_bwd_ipv4_header_len_mean = float(np.mean(flow_bwd_ipv4_header_lens))
            flow_bwd_ipv4_header_len_std = float(np.std(flow_bwd_ipv4_header_lens))
            flow_bwd_ipv4_header_len_var = float(np.var(flow_bwd_ipv4_header_lens))
            flow_bwd_ipv4_header_len_max = float(np.max(flow_bwd_ipv4_header_lens))
            flow_bwd_ipv4_header_len_min = float(np.min(flow_bwd_ipv4_header_lens))
            

        # ==========================
        # Packet Inter-arrival Times
        # ==========================

        # Packet IATs need at least 2 packets to be properly populated
        if len(flow_any_iats) == 0:
            flow_any_iat_total = flow_any_iat_mean = flow_any_iat_std = flow_any_iat_var = flow_any_iat_max = flow_any_iat_min = 0.0
        else:
            flow_any_iat_total = float(np.sum(flow_any_iats))
            flow_any_iat_mean = float(np.mean(flow_any_iats))
            flow_any_iat_std = float(np.std(flow_any_iats))
            flow_any_iat_var = float(np.var(flow_any_iats))
            flow_any_iat_max = float(np.max(flow_any_iats))
            flow_any_iat_min = float(np.min(flow_any_iats))

        # Packet IATs need at least 2 packets to be properly populated
        if len(flow_fwd_iats) == 0:
            flow_fwd_iat_total = flow_fwd_iat_mean = flow_fwd_iat_std = flow_fwd_iat_var =flow_fwd_iat_max = flow_fwd_iat_min = 0.0
        else:
            flow_fwd_iat_total = float(np.sum(flow_fwd_iats))
            flow_fwd_iat_mean = float(np.mean(flow_fwd_iats))
            flow_fwd_iat_std = float(np.std(flow_fwd_iats))
            flow_fwd_iat_var = float(np.var(flow_fwd_iats))
            flow_fwd_iat_max = float(np.max(flow_fwd_iats))
            flow_fwd_iat_min = float(np.min(flow_fwd_iats))

        # Packet IATs need at least 2 packets to be properly populated
        if len(flow_bwd_iats) == 0:
            flow_bwd_iat_total = flow_bwd_iat_mean = flow_bwd_iat_std = flow_bwd_iat_var = flow_bwd_iat_max = flow_bwd_iat_min = 0.0
        else:
            flow_bwd_iat_total = float(np.sum(flow_bwd_iats))
            flow_bwd_iat_mean = float(np.mean(flow_bwd_iats))
            flow_bwd_iat_std = float(np.std(flow_bwd_iats))
            flow_bwd_iat_var = float(np.var(flow_bwd_iats))
            flow_bwd_iat_max = float(np.max(flow_bwd_iats))
            flow_bwd_iat_min = float(np.min(flow_bwd_iats))

        # ======================
        # IP Fragmentation Flags
        # ======================
        flow_any_df_flags_total = float(np.sum(flow_any_df_flags))
        flow_any_df_flags_mean = float(np.mean(flow_any_df_flags))
        flow_any_df_flags_std = float(np.std(flow_any_df_flags))
        flow_any_df_flags_var = float(np.var(flow_any_df_flags))
        flow_any_df_flags_max = float(np.max(flow_any_df_flags))
        flow_any_df_flags_min = float(np.min(flow_any_df_flags))

        flow_fwd_df_flags_total = float(np.sum(flow_fwd_df_flags))
        flow_fwd_df_flags_mean = float(np.mean(flow_fwd_df_flags))
        flow_fwd_df_flags_std = float(np.std(flow_fwd_df_flags))
        flow_fwd_df_flags_var = float(np.var(flow_fwd_df_flags))
        flow_fwd_df_flags_max = float(np.max(flow_fwd_df_flags))
        flow_fwd_df_flags_min = float(np.min(flow_fwd_df_flags))

        flow_bwd_df_flags_total = float(np.sum(flow_bwd_df_flags))
        flow_bwd_df_flags_mean = float(np.mean(flow_bwd_df_flags))
        flow_bwd_df_flags_std = float(np.std(flow_bwd_df_flags))
        flow_bwd_df_flags_var = float(np.var(flow_bwd_df_flags))
        flow_bwd_df_flags_max = float(np.max(flow_bwd_df_flags))
        flow_bwd_df_flags_min = float(np.min(flow_bwd_df_flags))

        flow_any_mf_flags_total = float(np.sum(flow_any_mf_flags))
        flow_any_mf_flags_mean = float(np.mean(flow_any_mf_flags))
        flow_any_mf_flags_std = float(np.std(flow_any_mf_flags))
        flow_any_mf_flags_var = float(np.var(flow_any_mf_flags))
        flow_any_mf_flags_max = float(np.max(flow_any_mf_flags))
        flow_any_mf_flags_min = float(np.min(flow_any_mf_flags))

        flow_fwd_mf_flags_total = float(np.sum(flow_fwd_mf_flags))
        flow_fwd_mf_flags_mean = float(np.mean(flow_fwd_mf_flags))
        flow_fwd_mf_flags_std = float(np.std(flow_fwd_mf_flags))
        flow_fwd_mf_flags_var = float(np.var(flow_fwd_mf_flags))
        flow_fwd_mf_flags_max = float(np.max(flow_fwd_mf_flags))
        flow_fwd_mf_flags_min = float(np.min(flow_fwd_mf_flags))

        flow_bwd_mf_flags_total = float(np.sum(flow_bwd_mf_flags))
        flow_bwd_mf_flags_mean = float(np.mean(flow_bwd_mf_flags))
        flow_bwd_mf_flags_std = float(np.std(flow_bwd_mf_flags))
        flow_bwd_mf_flags_var = float(np.var(flow_bwd_mf_flags))
        flow_bwd_mf_flags_max = float(np.max(flow_bwd_mf_flags))
        flow_bwd_mf_flags_min = float(np.min(flow_bwd_mf_flags))

        # ===============
        # WRAP-UP RESULTS
        # ===============
        ipv4_flow_local_vars = locals()
        ipv4_flow_feature_values_list = [ipv4_flow_local_vars[var_name] for var_name in ipv4_flow_features_header_list]
        ipv4_flow_features_generator = dict(zip(ipv4_flow_features_header_list, ipv4_flow_feature_values_list))

        yield ipv4_flow_features_generator

def output_ipv4_flow_features(ipv4_flow_features_generator, output_type, over_ipv4=False):
    """
    Output all flows and their features with the following supported criteria:
        - L1: Ethernet
        - L2: Ethernet
        - L3: IPv4
        - L3plus: ICMP
        - L4: UDP, TCP
    """
    if output_type=="csv":
        ipv4_flow_features_header_str = get_flow_header_by_type("ipv4")
        ipv4_flow_features_csv = ipv4_flow_features_header_str + "\n"
        for ipv4_flow_features_dict in ipv4_flow_features_generator:
            ipv4_flow_features_list = list(ipv4_flow_features_dict.values())
            ipv4_flow_features_csv += generate_flow_line(ipv4_flow_features_list) + "\n"
        os.makedirs(csv_output_dir, exist_ok=True)
        f = open(csv_output_dir + os.sep + "ipv4-flows2.csv", "w")
        f.write(ipv4_flow_features_csv)
        f.close()

def generate_network_objets(file):
    """
    Build all network objects: flows, talkers and hosts
    """
    if args.verbose:
        run_init_time = time.time()

    # =======
    # PACKETS
    # =======
    packet_features = build_packets(file)

    # ====================
    # UNIDIRECTIONAL FLOWS
    # ====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("Unidirectional Layer3 Flows (IPv4)"), flush=True)

    uniflows, uniflow_ids = build_uniflows(packet_features)
    del(packet_features)

    if args.verbose:
        n_preserved_packets = 0
        for uniflow_id in uniflow_ids:
            n_preserved_packets += len(uniflows[uniflow_id])
        print("Number of packets preserved:", n_preserved_packets, "packets", flush=True)
        print("Number of flows detected:" + cterminal.colors.GREEN, len(uniflow_ids), "unidirectional flows" + cterminal.colors.ENDC, flush=True)
        print("Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # ===================
    # BIDIRECTIONAL FLOWS
    # ===================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("Bidirectional Layer3 Flows (IPv4)"), flush=True)

    biflows, biflow_ids = build_biflows(uniflows, uniflow_ids)
    del(uniflows)
    del(uniflow_ids)

    if args.verbose:
        n_preserved_packets = 0
        for biflow_id in biflow_ids:
            n_preserved_packets += len(biflows[biflow_id])
        print("Number of packets preserved:", n_preserved_packets, "packets", flush=True)
        print("Number of flows detected:" + cterminal.colors.GREEN, len(biflows), "bidirectional flows" + cterminal.colors.ENDC, flush=True)
        print("Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    # ==================
    # IPv4 Flow Features
    # ==================

    # ==============================
    # IPv4 Flow Feature Calculations
    # ==============================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("IPv4 Flow Feature Calculations"), flush=True)

    ipv4_flow_features_generator = calculate_ipv4_flow_features(biflows, biflow_ids)

    if args.verbose:
        ipv4_n_flow_features = get_flow_header_by_type("ipv4").count("|") - 2
        print("Number of calculated IPv4 flow features:" + cterminal.colors.GREEN, ipv4_n_flow_features, "L3 flow features" + cterminal.colors.ENDC, flush=True)
        print("Calculated in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True)

    # ========================
    # IPv4 Flow Feature Output
    # ========================
    if args.verbose:
        module_init_time = time.time()

    output_ipv4_flow_features(ipv4_flow_features_generator, args.output_type)

    if args.verbose:
        print("Saved in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")

    """
    # =======================
    # PLACEHOLDER: ICMP FLOWS
    # =======================
    # TODO: ICMP FLOWS

    # ======================
    # PLACEHOLDER: UDP FLOWS
    # ======================
    # TODO: UDP FLOWS

    # ===============================
    # TCP FLOWS (TCP Flag separation)
    # ===============================
    tcp_flows, tcp_flow_ids = build_tcp_flows(flows, flow_ids)
    del(flows)
    del(flow_ids)
    # NOTE: At this point, tcp_flow_ids are ordered by the flow start time and the packets in each flow are internally ordered by their timestamp
    # Error case
    if len(tcp_flows) == 0:
        print("This pcap doesn't have any communication that satisfies our TCP flow definition. Abort.", flush=True)
        exit()
    # Print some information about the built TCP flows
    if args.verbose:
        n_preserved_packets = 0
        for tcp_flow_id in tcp_flow_ids:
            n_preserved_packets += len(tcp_flows[tcp_flow_id])
        print("########## IPv4-TCP FLOWS (Bidirectional; TCP flag separation) ##########", flush=True)
        print("Number of IPv4-TCP flows:" + cterminal.colors.GREEN, str(len(tcp_flows)) + cterminal.colors.ENDC, flush=True)
        print("Number of packets preserved in these flows:" + cterminal.colors.GREEN, str(n_preserved_packets) + cterminal.colors.ENDC, flush=True)
    """
    # this should be done before... need to refactor all this into smaller classes
    #tcp_flow_features_generator = calculate_ipv4_flow_features(tcp_flows, tcp_flow_ids)
    #del(tcp_flows)
    #output_ipv4_flow_features(tcp_flow_features_generator, "csv")

    if args.verbose:
        print(make_header_string("Total Extraction Time"), flush=True)
        print("Script took" + cterminal.colors.YELLOW, round(time.time() - run_init_time, 3), "seconds" + cterminal.colors.ENDC, "to run", flush=True)

def run():
    print("Input PCAP file:"  + cterminal.colors.BLUE, args.pcap_path + cterminal.colors.ENDC, flush=True)
    supported_output_types = ("csv",)
    if args.output_type not in supported_output_types:
        print("Specified output type", cterminal.colors.BLUE + args.output_type + cterminal.colors.ENDC, "is not a valid output type.", flush=True)
        print("Valid output types:" + cterminal.colors.BLUE, ",".join(supported_output_types) + cterminal.colors.ENDC, flush=True)
        exit()
    print("Working on it...", flush=True)
    if args.output_type=="csv":
        print("Output CSV file:" + cterminal.colors.BLUE, csv_output_dir, cterminal.colors.ENDC, flush=True)

    if args.verbose:
        print("")
        print(make_header_string("VERBOSE OUTPUT ACTIVATED", separator="+", big_header=True), flush=True)
        print(make_header_string("SUPPORTED PROTOCOLS"), flush=True)
        print("Layer 1: Ethernet", flush=True)
        print("Layer 2: Ethernet", flush=True)
        print("Layer 3: IPv4", flush=True)
        print("Layer 3+: ICMPv4", flush=True)
        print("Layer 4: TCP, UDP", flush=True, end="\n\n")

    with open(args.pcap_path, "rb") as f:
        generate_network_objets(f)

if __name__ == "__main__":
    run()
