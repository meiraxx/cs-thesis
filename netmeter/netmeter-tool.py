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
# L3-protocols: **IPv4 (IP-4)**, ??ICMPv4 (IP-1)??, IPv6 (IP-41),  ICMPv6 (IP-58), GRE (IP-47)
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
# =====================
#     CLI OPTIONS
# =====================

oparser = argparse.ArgumentParser(prog="NetMeter", description="Network-based feature extraction tool")
oparser.add_argument("files", metavar="file", nargs="+", help="input pcap file")
#oparser.add_argument("-l", "--flow-label", help="label all flows as X", dest="flow_label", default="unknown")
#oparser.add_argument("-o", "--out-dir", help="output directory", dest="outdir", default="." + os.sep)
oparser.add_argument("-c", "--check-transport-data-length", action="store_true", help="check transport data length", dest="check_transport_data_length")
oparser.add_argument("-v", "--verbose", action="store_true", help="verbose output", dest="verbose")
args = oparser.parse_args()
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
datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
datetime_format2 = "%Y-%m-%d %H:%M:%S"
time_scale_factor = 1000.0

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

def datetime_to_unix_time_millis(dt):
    time_scale_factor = 1000.0
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * time_scale_factor

def unix_time_millis_to_datetime(ms_timestamp):
    time_scale_factor = 1000.0
    # NOTE: I think I put it here in case there was a "perfect" timestamp, in which case the %f wouldn't work out 
    #try:
    dt = datetime.datetime.utcfromtimestamp(ms_timestamp/time_scale_factor).strftime(datetime_format1)
    #except ValueError:
    #    dt = datetime.datetime.utcfromtimestamp(ms_timestamp/1000.0).strftime(datetime_format2)
    return dt

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

# ========================
# END: Auxiliary Functions
# ========================

# BIG-TODO: Need to improve my previous code because a lot of code is reusable, and a lot of code is just hardcoded.
def build_packets(file):
    """
    Process PCAP and build packets
    """
    #total_n_packets = sum(1 for packet in dpkt.pcap.Reader(file))
    file.seek(0)
    pcap = dpkt.pcap.Reader(file)
    n_packets = 0
    n_packets_tcp = 0
    n_packets_udp = 0
    #n_packets_icmp = 0

    # ethernet frame minimum size (minimum packet length)
    packet_len_minimum = 64

    # TODO: https://dpkt.readthedocs.io/en/latest/print_icmp.html
    # TODO: find a database and dataset format which accomodates such diverse feature formats (tcp vs udp vs icmp) while maintaining
    # all the relevant features for each format... maybe there needs to be dataset separation, or maybe it's enough to put a "L3-protocol"
    # and "L4-protocol" field to separate those formats in the same dataset and zero-out different values
    packets = []
    
    # [+] PARSE ALL PACKETS
    for timestamp, buf in pcap:
        # ================
        # LAYER1: ETHERNET
        # ================
        # Unpack the Ethernet frame (mac src, mac dst, ether type)
        eth = dpkt.ethernet.Ethernet(buf)

        # ================
        # LAYER2: ETHERNET
        # ================
        # Check if the Ethernet data contains an IP packet. If it doesn't, ignore it.
        if not isinstance(eth.data, dpkt.ip.IP):
            # FUTURE-TODO: implement handlers for other L3 protocols
            continue

        # ============
        # LAYER3: IPv4
        # ============
        # Unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Pull out fragment information
        df_flag = int(ip.off & dpkt.ip.IP_DF)
        mf_flag = int(ip.off & dpkt.ip.IP_MF)

        transport_layer = ip.data
        transport_protocol_name = type(transport_layer).__name__

        if transport_protocol_name in ("TCP", "UDP"):
            n_packets += 1  
            if transport_protocol_name == "UDP":
                n_packets_udp += 1

            if transport_protocol_name == "TCP":
                ip_header_len = ip.__hdr_len__ + len(ip.opts)
                transport_header_len = transport_layer.__hdr_len__ + len(transport_layer.opts)
                header_len = 14 + ip_header_len + transport_header_len    # header definition includes all except tcp.data (ip header, ip options, tcp header, tcp options)
                packet_len_tmp = len(buf)

                # ethernet zero-byte padding until 64 bytes are reached
                if packet_len_tmp >= packet_len_minimum:
                    packet_len = packet_len_tmp
                    # packet size (tcp data length)
                    packet_size = packet_len - header_len
                else:
                    eth_padding_bytes = packet_len_tmp - header_len
                    # header len will ignore eth padding bytes
                    # in this case, packet_len = header_len
                    packet_len = packet_len_tmp - eth_padding_bytes
                    # ethernet zero-byte padding until 64 bytes are reached
                    packet_size = packet_len - header_len

                # TODO: re-check this if-statement
                if packet_size != len(transport_layer.data) and args.check_transport_data_length:
                    print("Error on packet no." + str(n_packets) + ". Packet size should always correspond to tcp data length.", flush=True)
                    print(len(transport_layer.data), "!=", packet_size, flush=True)
                    exit()

                src_ip = inet_to_str(ip.src)
                src_port = transport_layer.sport
                dst_ip = inet_to_str(ip.dst)
                dst_port = transport_layer.dport


                # 6-tuple: src ip, src port, dst ip, dst port, protocol_stack, inner_sep_counter
                # note: inner_sep_counter is incremented whenever a flow reaches its end,
                # independently of the protocol used
                flow_id = (src_ip, src_port, dst_ip, dst_port, transport_protocol_name, 0)
                
                if transport_protocol_name == "TCP":
                    n_packets_tcp += 1
                    fin_flag = ( transport_layer.flags & dpkt.tcp.TH_FIN ) != 0
                    syn_flag = ( transport_layer.flags & dpkt.tcp.TH_SYN ) != 0
                    rst_flag = ( transport_layer.flags & dpkt.tcp.TH_RST ) != 0
                    psh_flag = ( transport_layer.flags & dpkt.tcp.TH_PUSH) != 0
                    ack_flag = ( transport_layer.flags & dpkt.tcp.TH_ACK ) != 0
                    urg_flag = ( transport_layer.flags & dpkt.tcp.TH_URG ) != 0
                    ece_flag = ( transport_layer.flags & dpkt.tcp.TH_ECE ) != 0
                    cwr_flag = ( transport_layer.flags & dpkt.tcp.TH_CWR ) != 0

                    packet_features = (flow_id, str(datetime.datetime.utcfromtimestamp(timestamp)), packet_len, header_len, packet_size, \
                        df_flag, mf_flag, fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag, ece_flag, cwr_flag)
                packets.append(packet_features)

                # FUTURE-TODO: IPv6 address test and consider database/dataset consequences
                src_ip_obj = ipaddress.IPv4Address(src_ip)
                dst_ip_obj = ipaddress.IPv4Address(dst_ip)
                #src_ip_sql_repr = hex(int(src_ip_obj))[2:]
                #dst_ip_sql_repr = hex(int(dst_ip_obj))[2:]

    if args.verbose:
        print("########## PACKETS ##########", flush=True)
        print("Total number of packets:",n_packets, flush=True)
        print("Number of UDP packets:",n_packets_udp, flush=True)
        print("Number of TCP packets:",n_packets_tcp, flush=True)
    return packets

def build_uniflows(packets):
    """Associate uniflow_ids to packets"""
    uniflows = dict()
    uniflow_ids = list()
    for packet in packets:
        flow_id = packet[0]
        uniflow_ids.append(flow_id)
        #if flow_id in uniflows:
        try:
            uniflows[flow_id].append(packet)
        except KeyError:
            uniflows[flow_id] = [packet]
    uniflow_ids = list(OrderedDict.fromkeys(uniflow_ids))             #remove duplicates mantaining order
    return uniflows, uniflow_ids

def join_duplicate_uniflows(uniflow_ids):
    """Join unidirectional flows with their counterpart (flows/conversations)"""
    unique_uniflow_ids = list()
    for uniflow_id in uniflow_ids:
        try:
            custom_items = [ unique_uniflow_ids[i] for i in range(5) ]
        except IndexError:
            custom_items = list()
        if uniflow_id[0:-1] not in custom_items:
            unique_uniflow_ids.append(uniflow_id)
            unique_uniflow_ids.append((uniflow_id[2],uniflow_id[3],uniflow_id[0],uniflow_id[1],uniflow_id[4],uniflow_id[5]))
    return list(OrderedDict.fromkeys(unique_uniflow_ids))

def build_flows(uniflows, unique_uniflow_ids):
    """Join unidirectional flow information into its bidirectional flow equivalent"""
    flows=dict()
    #non-separated flow ids (flows that haven't yet taken into account the begin/end flow flags)
    flow_ids=[]
    j=0
    n_unique_uniflow_ids = len(unique_uniflow_ids)
    while(j < n_unique_uniflow_ids):
        uniflow_id = unique_uniflow_ids[j]
        duplicate_id = unique_uniflow_ids[j+1]
        # have in mind every uniflow_id in this list will have been constituted by the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet
        flow_ids.append(uniflow_id)
        try:
            flows[uniflow_id] = uniflows[uniflow_id] + uniflows[duplicate_id]
        except KeyError:
            flows[uniflow_id] = uniflows[uniflow_id]
        j+=2
    return flows, flow_ids

def build_tcpflows(flows, flow_ids):
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
        """
        if flow_id[4] == "UDP": #udp flow
            tcp_flows[flow_id] = curr_flow
            tcp_flow_ids.append(flow_id)
            print("udp")
            continue
        """
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

def get_network_object_header(protocol_stack):
    flow_features_header_str = ""
    if protocol_stack == "ipv4":
        f = open("network-objects" + os.sep + "features" + os.sep + "ipv4-flow-header.txt", "r")
        flow_features_header_str = f.read().replace("\n", "|")
        f.close()
    else:
        raise ValueError("Protocol stack \"" + protocol_stack + "\" not supported. Supported protocol stacks: ipv4")
    return flow_features_header_str

def calculate_ipv4_flow_features(flows, flow_ids):
    """Calculate and output IPv4 flow features"""
    #"flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count,"+\
    #"flow_fwd_fin_count,flow_fwd_syn_count,flow_fwd_rst_count,flow_fwd_psh_count,flow_fwd_ack_count,flow_fwd_urg_count,flow_fwd_ece_count,flow_fwd_cwr_count,"+\
    #"flow_bwd_fin_count,flow_bwd_syn_count,flow_bwd_rst_count,flow_bwd_psh_count,flow_bwd_ack_count,flow_bwd_urg_count,flow_bwd_ece_count,flow_bwd_cwr_count,"+\

    ipv4_flow_features_header_str = get_network_object_header("ipv4")
    ipv4_flow_features_header_list = ipv4_flow_features_header_str.split("|")

    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        # NOTE: curr_flow[packet_index][packet_feature_index]

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

        # ====================
        # Packet Size Features
        # ====================
        flow_any_packet_lens = list()
        flow_fwd_packet_lens = list()
        flow_bwd_packet_lens = list()

        flow_any_header_lens = list()
        flow_fwd_header_lens = list()
        flow_bwd_header_lens = list()

        flow_any_packet_sizes = list()
        flow_fwd_packet_sizes = list()
        flow_bwd_packet_sizes = list()

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
        i = 0
        while i < flow_any_n_packets:
            previous_packet = curr_flow[i-1]
            previous_packet_flow_id = previous_packet[0]
            previous_packet_timestamp = previous_packet[1]

            curr_packet = curr_flow[i]
            curr_packet_flow_id = curr_packet[0]
            curr_packet_timestamp = curr_packet[1]
            curr_packet_len = curr_packet[2]
            curr_packet_header_len = curr_packet[3]
            curr_packet_size = curr_packet[4]
            curr_packet_df_flag = curr_packet[5]
            curr_packet_mf_flag = curr_packet[6]

            curr_tcp_flags = curr_packet[-8:]

            # start on second packet
            if i >= 1:
                try:
                    flow_any_first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(previous_packet_timestamp, datetime_format1))
                except ValueError:
                    flow_any_first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(previous_packet_timestamp, datetime_format2))
                try:
                    second_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_packet_timestamp, datetime_format1))
                except ValueError:
                    second_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_packet_timestamp, datetime_format2))
                curr_iat = (second_packet_time - flow_any_first_packet_time)/time_scale_factor
                flow_any_iats.append(curr_iat)
                if previous_packet_flow_id == flow_id:
                    flow_fwd_iats.append(curr_iat)
                else:
                    flow_bwd_iats.append(curr_iat)

            flow_any_packet_lens.append(curr_packet_len)
            flow_any_header_lens.append(curr_packet_header_len)
            flow_any_packet_sizes.append(curr_packet_size)
            flow_any_df_flags.append(curr_packet_df_flag)
            flow_any_mf_flags.append(curr_packet_mf_flag)

            if curr_packet_flow_id == flow_id:
                flow_fwd_packet_lens.append(curr_packet_len)
                flow_fwd_header_lens.append(curr_packet_header_len)
                flow_fwd_packet_sizes.append(curr_packet_size)
                flow_fwd_df_flags.append(curr_packet_df_flag)
                flow_fwd_mf_flags.append(curr_packet_mf_flag)

                flow_fwd_n_packets += 1
                if curr_packet_header_len != curr_packet_len:
                    flow_any_n_data_packets += 1
                    flow_fwd_n_data_packets += 1
            else:
                flow_bwd_packet_lens.append(curr_packet_len)
                flow_bwd_header_lens.append(curr_packet_header_len)
                flow_bwd_packet_sizes.append(curr_packet_size)
                flow_bwd_df_flags.append(curr_packet_df_flag)
                flow_bwd_mf_flags.append(curr_packet_mf_flag)

                flow_bwd_n_packets += 1
                if curr_packet_header_len != curr_packet_len:
                    flow_any_n_data_packets += 1
                    flow_bwd_n_data_packets += 1
            i+=1

        # ================================
        # ENRICH AND EXTRACT INFORMATION |
        # ================================

        # ========================================
        # number of packets (all times in seconds)
        # ========================================
        # [first packet][timestamp_index]
        try:
            flow_any_first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[0][1], datetime_format1))
        except ValueError:
            flow_any_first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[0][1], datetime_format2))

        # [last packet][timestamp_index]
        try:
            flow_any_last_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[flow_any_n_packets-1][1], datetime_format1))
        except ValueError:
            flow_any_last_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[flow_any_n_packets-1][1], datetime_format2))

        flow_any_duration = (flow_any_last_packet_time - flow_any_first_packet_time)/time_scale_factor
        if flow_any_duration == 0:
            flow_any_packets_per_sec = flow_fwd_packets_per_sec = flow_bwd_packets_per_sec = 0
        else:
            flow_any_packets_per_sec = flow_any_n_packets/flow_any_duration
            flow_fwd_packets_per_sec = flow_fwd_n_packets/flow_any_duration
            flow_bwd_packets_per_sec = flow_bwd_n_packets/flow_any_duration

        # ==============
        # packet lengths
        # ==============
        flow_any_packet_len_total = float(np.sum(flow_any_packet_lens))
        flow_any_packet_len_mean = float(np.mean(flow_any_packet_lens))
        flow_any_packet_len_std = float(np.std(flow_any_packet_lens))
        flow_any_packet_len_var = float(np.var(flow_any_packet_lens))
        flow_any_packet_len_max = float(np.max(flow_any_packet_lens))
        flow_any_packet_len_min = float(np.min(flow_any_packet_lens))

        flow_fwd_packet_len_total = float(np.sum(flow_fwd_packet_lens))
        flow_fwd_packet_len_mean = float(np.mean(flow_fwd_packet_lens))
        flow_fwd_packet_len_std = float(np.std(flow_fwd_packet_lens))
        flow_fwd_packet_len_var = float(np.var(flow_fwd_packet_lens))
        flow_fwd_packet_len_max = float(np.max(flow_fwd_packet_lens))
        flow_fwd_packet_len_min = float(np.min(flow_fwd_packet_lens))

        if len(flow_bwd_packet_lens) != 0:
            flow_bwd_packet_len_total = float(np.sum(flow_bwd_packet_lens))
            flow_bwd_packet_len_mean = float(np.mean(flow_bwd_packet_lens))
            flow_bwd_packet_len_std = float(np.std(flow_bwd_packet_lens))
            flow_bwd_packet_len_var = float(np.var(flow_bwd_packet_lens))
            flow_bwd_packet_len_max = float(np.max(flow_bwd_packet_lens))
            flow_bwd_packet_len_min = float(np.min(flow_bwd_packet_lens))
        else:
            flow_bwd_packet_len_total = flow_bwd_packet_len_mean = flow_bwd_packet_len_std = flow_bwd_packet_len_var = flow_bwd_packet_len_max = flow_bwd_packet_len_min = 0

        # =============
        # bytes per sec
        # =============
        flow_any_bytes_per_sec = 0 if flow_any_duration == 0 else float(flow_any_packet_len_total/flow_any_duration)
        flow_fwd_bytes_per_sec = 0 if flow_any_duration == 0 else float(flow_fwd_packet_len_total/flow_any_duration)
        flow_bwd_bytes_per_sec = 0 if flow_any_duration == 0 else float(flow_bwd_packet_len_total/flow_any_duration)

        # ==================================================================
        # header lengths (14 byte Ether header + ip header + tcp/udp header)
        # ==================================================================
        flow_any_header_len_total = float(np.sum(flow_any_header_lens))
        flow_fwd_header_len_total = float(np.sum(flow_fwd_header_lens))
        flow_bwd_header_len_total = float(np.sum(flow_bwd_header_lens)) if len(flow_bwd_header_lens)!=0 else 0

        # ===========
        # packet size
        # ===========

        flow_any_packet_size_mean = float(np.mean(flow_any_packet_sizes))
        flow_any_packet_size_std = float(np.std(flow_any_packet_sizes))
        flow_any_packet_size_max = float(np.max(flow_any_packet_sizes))
        flow_any_packet_size_min = float(np.min(flow_any_packet_sizes))

        flow_fwd_packet_size_mean = float(np.mean(flow_fwd_packet_sizes))
        flow_fwd_packet_size_std = float(np.std(flow_fwd_packet_sizes))
        flow_fwd_packet_size_max = float(np.max(flow_fwd_packet_sizes))
        flow_fwd_packet_size_min = float(np.min(flow_fwd_packet_sizes))

        if len(flow_bwd_packet_sizes) != 0:
            flow_bwd_packet_size_mean = float(np.mean(flow_bwd_packet_sizes))
            flow_bwd_packet_size_std = float(np.std(flow_bwd_packet_sizes))
            flow_bwd_packet_size_max = float(np.max(flow_bwd_packet_sizes))
            flow_bwd_packet_size_min = float(np.min(flow_bwd_packet_sizes))
        else:
            flow_bwd_packet_size_mean = flow_bwd_packet_size_std = flow_bwd_packet_size_max = flow_bwd_packet_size_min = 0

        # ==========================
        # packet inter-arrival times
        # ==========================
        if len(flow_any_iats) != 0:
            flow_any_iat_total = float(np.sum(flow_any_iats))
            flow_any_iat_mean = float(np.mean(flow_any_iats))
            flow_any_iat_std = float(np.std(flow_any_iats))
            flow_any_iat_max = float(np.max(flow_any_iats))
            flow_any_iat_min = float(np.min(flow_any_iats))
        else:
            flow_any_iat_total = flow_any_iat_mean = flow_any_iat_std = flow_any_iat_max = flow_any_iat_min = 0

        if len(flow_fwd_iats) != 0:
            flow_fwd_iat_total = float(np.sum(flow_fwd_iats))
            flow_fwd_iat_mean = float(np.mean(flow_fwd_iats))
            flow_fwd_iat_std = float(np.std(flow_fwd_iats))
            flow_fwd_iat_max = float(np.max(flow_fwd_iats))
            flow_fwd_iat_min = float(np.min(flow_fwd_iats))
        else:
            flow_fwd_iat_total = flow_fwd_iat_mean = flow_fwd_iat_std = flow_fwd_iat_max = flow_fwd_iat_min = 0

        if len(flow_bwd_iats) != 0:
            flow_bwd_iat_total = float(np.sum(flow_bwd_iats))
            flow_bwd_iat_mean = float(np.mean(flow_bwd_iats))
            flow_bwd_iat_std = float(np.std(flow_bwd_iats))
            flow_bwd_iat_max = float(np.max(flow_bwd_iats))
            flow_bwd_iat_min = float(np.min(flow_bwd_iats))
        else:
            flow_bwd_iat_total = flow_bwd_iat_mean = flow_bwd_iat_std = flow_bwd_iat_max = flow_bwd_iat_min = 0

        # ==============
        # IP Flag Counts
        # ==============
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

        """
        flow_flag_counts = [0]*10
        for flags in flow_any_flags:
            for i,flag in enumerate(flags):
                if flag:
                    flow_flag_counts[i] += 1

        flow_fwd_flag_counts = [0]*10
        for flags in flow_fwd_flags:
            for i,flag in enumerate(flags):
                if flag:
                    flow_fwd_flag_counts[i] += 1

        flow_bwd_flag_counts = [0]*10
        for flags in flow_bwd_flags:
            for i,flag in enumerate(flags):
                if flag:
                    flow_bwd_flag_counts[i] += 1
        """
        ipv4_flow_feature_values_list = \
            [flow_id,flow_any_first_packet_time,flow_any_last_packet_time,flow_any_duration,\
            flow_any_n_packets,flow_fwd_n_packets,flow_bwd_n_packets,\
            flow_any_n_data_packets,flow_fwd_n_data_packets,flow_bwd_n_data_packets,\
            flow_any_header_len_total,flow_fwd_header_len_total,flow_bwd_header_len_total,\
            flow_any_packet_size_mean,flow_any_packet_size_std,flow_any_packet_size_max,\
            flow_any_packet_size_min,flow_fwd_packet_size_mean,flow_fwd_packet_size_std,flow_fwd_packet_size_max,flow_fwd_packet_size_min,flow_bwd_packet_size_mean,flow_bwd_packet_size_std,flow_bwd_packet_size_max,flow_bwd_packet_size_min,\
            flow_any_packets_per_sec,flow_fwd_packets_per_sec,flow_bwd_packets_per_sec,\
            flow_any_bytes_per_sec,flow_fwd_bytes_per_sec,flow_bwd_bytes_per_sec,\
            flow_any_packet_len_total,flow_any_packet_len_mean,flow_any_packet_len_std,flow_any_packet_len_var,flow_any_packet_len_max,flow_any_packet_len_min,\
            flow_fwd_packet_len_total,flow_fwd_packet_len_mean,flow_fwd_packet_len_std,flow_fwd_packet_len_var,flow_fwd_packet_len_max,flow_fwd_packet_len_min,\
            flow_bwd_packet_len_total,flow_bwd_packet_len_mean,flow_bwd_packet_len_std,flow_bwd_packet_len_var,flow_bwd_packet_len_max,flow_bwd_packet_len_min,\
            flow_any_iat_total,flow_any_iat_mean,flow_any_iat_std,flow_any_iat_max,flow_any_iat_min,\
            flow_fwd_iat_total,flow_fwd_iat_mean,flow_fwd_iat_std,flow_fwd_iat_max,flow_fwd_iat_min,\
            flow_bwd_iat_total,flow_bwd_iat_mean,flow_bwd_iat_std,flow_bwd_iat_max,flow_bwd_iat_min,\
            flow_any_df_flags_total,flow_any_df_flags_mean,flow_any_df_flags_std,flow_any_df_flags_var,flow_any_df_flags_max,flow_any_df_flags_min,\
            flow_fwd_df_flags_total,flow_fwd_df_flags_mean,flow_fwd_df_flags_std,flow_fwd_df_flags_var,flow_fwd_df_flags_max,flow_fwd_df_flags_min,\
            flow_bwd_df_flags_total,flow_bwd_df_flags_mean,flow_bwd_df_flags_std,flow_bwd_df_flags_var,flow_bwd_df_flags_max,flow_bwd_df_flags_min,\
            flow_any_mf_flags_total,flow_any_mf_flags_mean,flow_any_mf_flags_std,flow_any_mf_flags_var,flow_any_mf_flags_max,flow_any_mf_flags_min,\
            flow_fwd_mf_flags_total,flow_fwd_mf_flags_mean,flow_fwd_mf_flags_std,flow_fwd_mf_flags_var,flow_fwd_mf_flags_max,flow_fwd_mf_flags_min,\
            flow_bwd_mf_flags_total,flow_bwd_mf_flags_mean,flow_bwd_mf_flags_std,flow_bwd_mf_flags_var,flow_bwd_mf_flags_max,flow_bwd_mf_flags_min]

        ipv4_flow_features_generator = dict(zip(ipv4_flow_features_header_list, ipv4_flow_feature_values_list))

        yield ipv4_flow_features_generator

def output_ipv4_flow_features(ipv4_flow_features_generator, mode, over_ipv4=False):
    """
    Output all flows and their features with the following supported criteria:
        - L1: Ethernet
        - L2: Ethernet
        - L3: IPv4
        - L3plus: ICMP
        - L4: UDP, TCP
    """
    if mode=="csv":
        ipv4_flow_features_header_str = get_network_object_header("ipv4")
        ipv4_flow_features_csv = ipv4_flow_features_header_str + "\n"
        for ipv4_flow_features_dict in ipv4_flow_features_generator:
            ipv4_flow_features_list = list(ipv4_flow_features_dict.values())
            ipv4_flow_features_csv += generate_flow_line(ipv4_flow_features_list) + "\n"
        f = open("data-files" + os.sep + "csv" + os.sep +  "flows.csv", "w")
        f.write(ipv4_flow_features_csv)
        f.close()

def generate_network_objets(file):
    """
    Build all network objects: flows, talkers and hosts
    """
    start_time = time.time()

    # =======
    # PACKETS
    # =======
    packet_features = build_packets(file)

    # ========
    # UNIFLOWS
    # ========
    uniflows,uniflow_ids = build_uniflows(packet_features)
    del(packet_features)
    unique_uniflow_ids = join_duplicate_uniflows(uniflow_ids)
    del(uniflow_ids)

    if args.verbose:
        n_preserved_packets = 0
        for unique_uniflow_id in unique_uniflow_ids:
            n_preserved_packets += len(uniflows[unique_uniflow_id])
        print("########## FLOWS (Unidirectional; no in-flow separation) ##########", flush=True)
        print("Number of unidirectional flows:", len(unique_uniflow_ids), flush=True)
        print("Number of packets preserved in these flows:", n_preserved_packets, flush=True)
    

    # =====
    # FLOWS
    # =====
    flows,flow_ids = build_flows(uniflows, unique_uniflow_ids)
    del(uniflows)
    del(unique_uniflow_ids)

    if args.verbose:
        n_preserved_packets = 0
        for flow_id in flow_ids:
            n_preserved_packets += len(flows[flow_id])
        print("########## FLOWS (Bidirectional; no in-flow separation) ##########", flush=True)
        print("Number of bidirectional flows:", len(flows), flush=True)
        print("Number of packets preserved in these flows:", n_preserved_packets, flush=True)

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
    tcp_flows, tcp_flow_ids = build_tcpflows(flows, flow_ids)
    del(flows)
    del(flow_ids)
    # Note: At this point, tcp_flow_ids are ordered by the flow start time and the packets in each flow are internally ordered by their timestamp
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

    # this should be done before... need to refactor all this into smaller classes
    tcp_flow_features_generator = calculate_ipv4_flow_features(tcp_flows, tcp_flow_ids)
    del(tcp_flows)

    output_ipv4_flow_features(tcp_flow_features_generator, "csv")

    rounded_elapsed_time = round(time.time() - start_time, 2)
    print("########## Elapsed Time ##########", flush=True)
    print("Dataset generated in" + cterminal.colors.GREEN, str(rounded_elapsed_time), cterminal.colors.ENDC + "seconds", flush=True)

if __name__ == "__main__":
    filenames = args.files
    for filename in filenames:
        print("Parsing"  + cterminal.colors.GREEN, filename + cterminal.colors.ENDC + "...", flush=True)
        with open(filename, "rb") as f:
            generate_network_objets(f)
