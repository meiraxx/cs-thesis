#!/usr/bin/env python3

"""
This script is meant to output "hosts" (ipX), "talkers" (ipX-ipY) and "flows"
(ipX-portA-ipY-portB-protocol_stack-sep_counter) and their respective
conceptual and statistical features to build a dataset

AUTHORSHIP:
Joao Meira <joao.meira.cs@gmail.com>

"""

# ===============================================================
# OSI-layer protocols: https://en.wikipedia.org/wiki/List_of_network_protocols_(OSI_model)
# L0 (physical methods of propagation): Copper, Fiber, Wireless
# NetMeter Protocols
# L1-protocols: Ethernet (Physical Layer)
# L2-protocols: Ethernet, MAC, ARP
# https://en.wikipedia.org/wiki/EtherType; https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
# L3-protocols: IPv4 (IP-4), IPv6 (IP-41), ICMPv4 (IP-1), ICMPv6 (IP-58) GRE (IP-47)
# L4-protocols: TCP (IP-6), UDP (IP-17)
# ===============================================================

try:
    import dpkt
    import socket, ipaddress, datetime
    import numpy as np
    import time
    import argparse
    import os, sys
    #import localdbconnector

    from dpkt.compat import compat_ord
    from collections import OrderedDict
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")


# =====================
#     CLI OPTIONS
# =====================

oparser = argparse.ArgumentParser(prog="NetMeter",description="Network-based feature extraction tool")
oparser.add_argument("files", metavar="file", nargs="+", help="input pcap file")
oparser.add_argument("-l", "--label", help="label all flows as X", dest="label", default="unknown")
#oparser.add_argument("-o", "--out-dir", help="output directory", dest="outdir", default="." + os.sep)
oparser.add_argument("-c", "--check-transport-data-length", action="store_true", help="check transport data length", dest="check_transport_data_length")
oparser.add_argument("-v", "--verbose", action="store_true", help="verbose output", dest="verbose")
args = oparser.parse_args()
"""
args_list = [args.register!="", args.login!="",\
            args.listindividualfiles, args.sendindividualfiles!="", args.fetchindividualfiles!="", args.deleteindividualfiles!="",\
            args.listallusers, args.share!="", args.fetchshared!="", args.sendshared!="",\
            args.listmybackups, args.revert, args.revertshared]

if True not in args_list:
    print "[!][" + now() + "] You need to choose an option."
    oparser.print_help()
    exit()
"""
datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
datetime_format2 = "%Y-%m-%d %H:%M:%S"

# ===================
# Auxiliary Functions
# ===================

def flow_id_to_talker_id(flow_id):
    splitted_flow_id = flow_id.split("-")
    return splitted_flow_id[0] + "-" + splitted_flow_id[2]

def gen_flow_str(flow_features):
    return flow_id_to_str(flow_features[0]) + "," + ",".join(map(str,flow_features[1:])) + "\n"

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
    # FUTURE: handle IPv6
    ipv4_obj = ipaddress.IPv4Address(ipv4_dotted)
    ipv4_int = hex(int(ipv4_obj))[2:]
    return ipv4_int

def build_packets(file):
    """
    Process PCAP and build packets
    """
    #total_n_packets = sum(1 for packet in dpkt.pcap.Reader(file))
    file.seek(0)
    pcap = dpkt.pcap.Reader(file)
    n_packets=0
    n_packets_tcp=0
    n_packets_udp=0
    #n_packets_icmp=0

    # ethernet frame minimum size (minimum packet length)
    packet_len_minimum = 64

    # TODO: https://dpkt.readthedocs.io/en/latest/print_icmp.html
    # TODO: find a database and dataset format which accomodates such diverse feature formats (tcp vs udp vs icmp) while maintaining
    # all the relevant features for each format... maybe there needs to be dataset separation, or maybe it's enough to put a "L3-protocol"
    # and "L4-protocol" field to separate those formats in the same dataset and zero-out different values
    packets=[]

    #localdbconnector.delete_all("Flows")
    #localdbconnector.delete_all("Talker")
    #localdbconnector.delete_all("Hosts")
    
    # [+] PARSE ALL PACKETS
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src, mac dst, ether type)
        eth = dpkt.ethernet.Ethernet(buf)

        # Check if the Ethernet data contains an IP packet. If it doesn't, ignore it.
        if not isinstance(eth.data, dpkt.ip.IP):
            # FUTURE: implement handlers for other L3 protocols
            continue

        # Unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Pull out fragment information
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)

        transport_layer=ip.data
        transport_protocol_name=type(transport_layer).__name__

        if transport_protocol_name in ("TCP", "UDP"):
            n_packets+=1  
            if transport_protocol_name=="UDP":
                n_packets_udp+=1

            if transport_protocol_name=="TCP":
                ip_header_len = ip.__hdr_len__ + len(ip.opts)
                transport_header_len = transport_layer.__hdr_len__ + len(transport_layer.opts)
                header_len = 14 + ip_header_len + transport_header_len    # header definition includes all except tcp.data (ip header, ip options, tcp header, tcp options)
                packet_len_tmp = len(buf)

                # ethernet zero-byte padding until 64 bytes are reached
                if packet_len_tmp>=packet_len_minimum:
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
                if packet_size!=len(transport_layer.data) and args.check_transport_data_length:
                    print("Error on packet no." + str(n_packets) + ". Packet size should always correspond to tcp data length.", file=sys.stderr)
                    print(len(transport_layer.data),"!=",packet_size, file=sys.stderr)
                    exit()

                src_ip = inet_to_str(ip.src)
                src_port = transport_layer.sport
                dst_ip = inet_to_str(ip.dst)
                dst_port = transport_layer.dport


                # 6-tuple: src ip, src port, dst ip, dst port, protocol_stack, sep-counter
                # note: in-flow-counter is incremented whenever a flow reaches its end,
                # independently of the protocol used
                direction_id = (src_ip, src_port, dst_ip, dst_port, transport_protocol_name, 0)
                
                if transport_protocol_name=="TCP":
                    n_packets_tcp+=1
                    fin_flag = ( transport_layer.flags & dpkt.tcp.TH_FIN ) != 0
                    syn_flag = ( transport_layer.flags & dpkt.tcp.TH_SYN ) != 0
                    rst_flag = ( transport_layer.flags & dpkt.tcp.TH_RST ) != 0
                    psh_flag = ( transport_layer.flags & dpkt.tcp.TH_PUSH) != 0
                    ack_flag = ( transport_layer.flags & dpkt.tcp.TH_ACK ) != 0
                    urg_flag = ( transport_layer.flags & dpkt.tcp.TH_URG ) != 0
                    ece_flag = ( transport_layer.flags & dpkt.tcp.TH_ECE ) != 0
                    cwr_flag = ( transport_layer.flags & dpkt.tcp.TH_CWR ) != 0
                    packet_features = (direction_id, str(datetime.datetime.utcfromtimestamp(timestamp)), packet_len, header_len, packet_size, \
                        do_not_fragment, more_fragments, fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag, ece_flag, cwr_flag)
                elif transport_protocol_name=="UDP":
                    packet_features = (direction_id, str(datetime.datetime.utcfromtimestamp(timestamp)), packet_len, header_len, packet_size, \
                        do_not_fragment, more_fragments)
                packets.append(packet_features)

                # FUTURE: IPv6 address test and consider database/dataset consequences
                src_ip_obj = ipaddress.IPv4Address(src_ip)
                dst_ip_obj = ipaddress.IPv4Address(dst_ip)
                #src_ip_sql_repr = hex(int(src_ip_obj))[2:]
                #dst_ip_sql_repr = hex(int(dst_ip_obj))[2:]

    if args.verbose:
        print("Total number of packets:",n_packets, file=sys.stderr)
        print("########## PACKETS ##########", file=sys.stderr)
        print("Number of UDP packets:",n_packets_udp, file=sys.stderr)
        print("Number of TCP packets:",n_packets_tcp, file=sys.stderr)
    return packets

def build_uniflows(packets):
    """Associate uniflow_ids to packets"""
    uniflows = dict()
    uniflow_ids = list()
    for packet in packets:
        direction_id = packet[0]
        uniflow_ids.append(direction_id)
        #if direction_id in uniflows:
        try:
            uniflows[direction_id].append(packet)
        except KeyError:
            uniflows[direction_id] = [packet]
    uniflow_ids=list(OrderedDict.fromkeys(uniflow_ids))             #remove duplicates mantaining order
    if args.verbose:
        print("########## Flows (Unidirectional) ##########", file=sys.stderr)
        print("Number of unidirectional flows (w/o flag separation):",len(uniflow_ids), file=sys.stderr)
    return uniflows,uniflow_ids

def parse_duplicate_uniflows(uniflow_ids):
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
    if args.verbose:
        print("########## Flows (Bidirectional) ##########")
        print("Number of flows:",len(flow_ids))
    return flows, flow_ids

def build_tcpflows(flows, tcp_flow_ids):
    """Separate bidirectional flows using TCP's RFC rules"""
    # FUTURE: validate using tcp_seq
    # fin,syn,rst,psh,ack,urg,ece,cwr (2,...,9)
    tcp_flows = dict()
    # ordered flow keys (by flow start time)
    tcp_flow_ids = []

    # create conventionally correct flows
    for tcp_flow_id in tcp_flow_ids:
        flow = tcp_flows[tcp_flow_id]
        flow.sort(key=lambda x: x[1])       # sorting the packets in each flow by date-and-time
        if tcp_flow_id[4]=="UDP": #udp flow
            tcp_flows[tcp_flow_id] = flow
            tcp_flow_ids.append(tcp_flow_id)
            continue
        flow_n_packets = len(flow)

        if flow_n_packets==0:
            raise ValueError("A flow can't have 0 packets.")
        elif flow_n_packets in (1,2,3):     #1/2/3 pacotes num so flow_id perfazem no maximo 1 e 1 so tcp flow
            tcp_flows[tcp_flow_id] = flow
            tcp_flow_ids.append(tcp_flow_id)
        else:
            i=0
            last_i=0
            flow_begin=False
            sep_counter=0
            while i < flow_n_packets:
                fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1=flow[i][-8:]
                if i==flow_n_packets-2:   # penultimate packet
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2=flow[i+1][-8:]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3=[False]*8
                elif i==flow_n_packets-1: # last packet
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2=[False]*8
                    fin3,syn3,rst3,psh3,ack3,urg2,ece3,cwr3=[False]*8
                else:               # other packets
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2=flow[i+1][-8:]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3=flow[i+2][-8:]

                ###### TCP FLOW RULES ######
                # r1,r2: begin flow
                r1 = (syn1 and not ack1) and (syn2 and ack2) and ack3           # 3-way handshake (full-duplex), syn+syn-ack+ack / syn+syn-ack+syn-ack
                r2 = (syn1 and not ack1) and ack2                               # 2-way handshake (half-duplex), syn+syn-ack / syn+ack
                # r3,r4: end flow
                r3 = fin1 and (fin2 and ack2) and ack3
                r4 = rst1 and not rst2

                # consider flow begin or ignore it (considering it is safer, but not considering it will leave out flows that have started before the capture)
                # the only rule used will be the half-duplex handshake rule because it is inclusive of the full-duplex handshake rule,
                # i.e., (r2 or r1) == r2, for any flow
                if r2:
                    flow_begin=True

                # we consider flows only the ones that start with a 2 or 3-way handshake (r1,r2)
                # the flow end conditions are r3 and r4, (fin,fin-ack,ack)/(rst,!rst,---), or if the packet is the last one of the existing communication
                if flow_begin:
                    if r3:
                        new_tcp_flow_id=(tcp_flow_id[0],tcp_flow_id[1],tcp_flow_id[2],tcp_flow_id[3],tcp_flow_id[4],tcp_flow_id[5]+sep_counter)
                        tcp_flows[new_tcp_flow_id] = flow[last_i:i+3]
                        tcp_flow_ids.append(new_tcp_flow_id)
                        flow_begin=False
                        last_i=i+3
                        sep_counter+=1
                    elif r4 or i==flow_n_packets-1:
                        new_tcp_flow_id=(tcp_flow_id[0],tcp_flow_id[1],tcp_flow_id[2],tcp_flow_id[3],tcp_flow_id[4],tcp_flow_id[5]+sep_counter)
                        tcp_flows[new_tcp_flow_id] = flow[last_i:i+1]
                        tcp_flow_ids.append(new_tcp_flow_id)
                        flow_begin=False
                        last_i=i+1
                        sep_counter+=1
                i+=1
    return tcp_flows,tcp_flow_ids

def calculate_tcpflow_features(flows, flow_ids):
    """Calculate and output flow features"""
    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        flow_n_packets = len(curr_flow)
        # [first packet][flow_id_index]
        direction_id = curr_flow[0][0]
        flow_iats = list()
        fwd_iats = list()
        bwd_iats = list()
        flow_packet_lens = list()
        fwd_packet_lens = list()
        bwd_packet_lens = list()
        flow_header_lens = list()
        fwd_header_lens = list()
        bwd_header_lens = list()
        flow_packet_sizes = list()
        fwd_packet_sizes = list()
        bwd_packet_sizes = list()
        flow_n_data_packets = 0
        fwd_n_data_packets = 0
        bwd_n_data_packets = 0
        flow_flags = list()
        fwd_flags = list()
        bwd_flags = list()

        i = 0
        while i < flow_n_packets:
            if i >= 1:
                try:
                    first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[i-1][1], datetime_format1))
                except ValueError:
                    first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[i-1][1], datetime_format2))
                try:
                    second_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[i][1], datetime_format1))
                except ValueError:
                    second_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[i][1], datetime_format2))
                current_iat = (second_packet_time - first_packet_time)/time_scale_factor
                flow_iats.append(current_iat)
                if curr_flow[i-1][0]==direction_id:
                    fwd_iats.append(current_iat)
                else:
                    bwd_iats.append(current_iat)

            current_packet_len = curr_flow[i][2]
            current_header_len = curr_flow[i][3]
            current_packet_size = curr_flow[i][4]
            current_flags = curr_flow[i][-10:]

            flow_flags.append(current_flags)
            flow_packet_lens.append(current_packet_len)
            flow_header_lens.append(current_header_len)
            flow_packet_sizes.append(current_packet_size)

            if curr_flow[i][0]==direction_id:
                fwd_packet_lens.append(current_packet_len)
                fwd_header_lens.append(current_header_len)
                fwd_packet_sizes.append(current_packet_size)
                fwd_flags.append(current_flags)
                if current_header_len != current_packet_len:
                    flow_n_data_packets+=1
                    fwd_n_data_packets+=1
            else:
                bwd_packet_lens.append(current_packet_len)
                bwd_header_lens.append(current_header_len)
                bwd_packet_sizes.append(current_packet_size)
                bwd_flags.append(current_flags)
                if current_header_len != current_packet_len:
                    flow_n_data_packets+=1
                    bwd_n_data_packets+=1
            i+=1

        # number of packets (all times in seconds)
        # [first packet][timestamp_index]
        try:
            first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[0][1], datetime_format1))
        except ValueError:
            first_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[0][1], datetime_format2))

        # [last packet][timestamp_index]
        try:
            last_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[flow_n_packets-1][1], datetime_format1))
        except ValueError:
            last_packet_time = datetime_to_unix_time_millis(datetime.datetime.strptime(curr_flow[flow_n_packets-1][1], datetime_format2))
        flow_duration = (last_packet_time - first_packet_time)/time_scale_factor

        fwd_n_packets = len(fwd_packet_lens)
        bwd_n_packets = len(bwd_packet_lens)

        if flow_duration==0:
            flow_packets_per_sec = fwd_packets_per_sec = bwd_packets_per_sec = 0
        else:
            flow_packets_per_sec = flow_n_packets/flow_duration
            fwd_packets_per_sec = fwd_n_packets/flow_duration
            bwd_packets_per_sec = bwd_n_packets/flow_duration

        # packet lengths
        flow_packet_len_total = float(np.sum(flow_packet_lens))
        flow_packet_len_mean = float(np.mean(flow_packet_lens))
        flow_packet_len_std = float(np.std(flow_packet_lens))
        flow_packet_len_var = float(np.var(flow_packet_lens))
        flow_packet_len_max = float(np.max(flow_packet_lens))
        flow_packet_len_min = float(np.min(flow_packet_lens))

        fwd_packet_len_total = float(np.sum(fwd_packet_lens))
        fwd_packet_len_mean = float(np.mean(fwd_packet_lens))
        fwd_packet_len_std = float(np.std(fwd_packet_lens))
        fwd_packet_len_var = float(np.var(fwd_packet_lens))
        fwd_packet_len_max = float(np.max(fwd_packet_lens))
        fwd_packet_len_min = float(np.min(fwd_packet_lens))

        if len(bwd_packet_lens)!=0:
            bwd_packet_len_total = float(np.sum(bwd_packet_lens))
            bwd_packet_len_mean = float(np.mean(bwd_packet_lens))
            bwd_packet_len_std = float(np.std(bwd_packet_lens))
            bwd_packet_len_var = float(np.var(bwd_packet_lens))
            bwd_packet_len_max = float(np.max(bwd_packet_lens))
            bwd_packet_len_min = float(np.min(bwd_packet_lens))
        else:
            bwd_packet_len_total = bwd_packet_len_mean = bwd_packet_len_std = bwd_packet_len_var = bwd_packet_len_max = bwd_packet_len_min = 0

        # bytes per sec
        flow_bytes_per_sec = 0 if flow_duration==0 else float(flow_packet_len_total/flow_duration)
        fwd_bytes_per_sec = 0 if flow_duration==0 else float(fwd_packet_len_total/flow_duration)
        bwd_bytes_per_sec = 0 if flow_duration==0 else float(bwd_packet_len_total/flow_duration)

        # header lengths (14 byte Ether header + ip header + tcp/udp header)
        flow_header_len_total = float(np.sum(flow_header_lens))
        fwd_header_len_total = float(np.sum(fwd_header_lens))
        bwd_header_len_total = float(np.sum(bwd_header_lens)) if len(bwd_header_lens)!=0 else 0

        # packet size
        flow_packet_size_mean = float(np.mean(flow_packet_sizes))
        flow_packet_size_std = float(np.std(flow_packet_sizes))
        flow_packet_size_max = float(np.max(flow_packet_sizes))
        flow_packet_size_min = float(np.min(flow_packet_sizes))

        fwd_packet_size_mean = float(np.mean(fwd_packet_sizes))
        fwd_packet_size_std = float(np.std(fwd_packet_sizes))
        fwd_packet_size_max = float(np.max(fwd_packet_sizes))
        fwd_packet_size_min = float(np.min(fwd_packet_sizes))

        if len(bwd_packet_sizes)!=0:
            bwd_packet_size_mean = float(np.mean(bwd_packet_sizes))
            bwd_packet_size_std = float(np.std(bwd_packet_sizes))
            bwd_packet_size_max = float(np.max(bwd_packet_sizes))
            bwd_packet_size_min = float(np.min(bwd_packet_sizes))
        else:
            bwd_packet_size_mean = bwd_packet_size_std = bwd_packet_size_max = bwd_packet_size_min = 0


        # packet inter-arrival times
        if len(flow_iats)!=0:
            flow_iat_total = float(np.sum(flow_iats))
            flow_iat_mean = float(np.mean(flow_iats))
            flow_iat_std = float(np.std(flow_iats))
            flow_iat_max = float(np.max(flow_iats))
            flow_iat_min = float(np.min(flow_iats))
        else:
            flow_iat_total = flow_iat_mean = flow_iat_std = flow_iat_max = flow_iat_min = 0

        if len(fwd_iats)!=0:
            fwd_iat_total = float(np.sum(fwd_iats))
            fwd_iat_mean = float(np.mean(fwd_iats))
            fwd_iat_std = float(np.std(fwd_iats))
            fwd_iat_max = float(np.max(fwd_iats))
            fwd_iat_min = float(np.min(fwd_iats))
        else:
            fwd_iat_total = fwd_iat_mean = fwd_iat_std = fwd_iat_max = fwd_iat_min = 0

        if len(bwd_iats)!=0:
            bwd_iat_total = float(np.sum(bwd_iats))
            bwd_iat_mean = float(np.mean(bwd_iats))
            bwd_iat_std = float(np.std(bwd_iats))
            bwd_iat_max = float(np.max(bwd_iats))
            bwd_iat_min = float(np.min(bwd_iats))
        else:
            bwd_iat_total = bwd_iat_mean = bwd_iat_std = bwd_iat_max = bwd_iat_min = 0


        # TODO: I think these lines are kind of hardcoded... can I do better later? :)
        # flag counts (ip/tcp)
        flow_flag_counts = [0]*10
        for flags in flow_flags:
            for i,flag in enumerate(flags):
                if flag:
                    flow_flag_counts[i]+=1

        fwd_flag_counts = [0]*10
        for flags in fwd_flags:
            for i,flag in enumerate(flags):
                if flag:
                    fwd_flag_counts[i]+=1

        bwd_flag_counts = [0]*10
        for flags in bwd_flags:
            for i,flag in enumerate(flags):
                if flag:
                    bwd_flag_counts[i]+=1

        # TODO: use the flow file to get header
        # TODO: get keys from MD file(s), always updated
        # TODO: why would I put this inside the cycle? :) need to put it out of the cycle to optimize performance.
        tcp_flow_features_header_str = "flow_id,flow_start_time,flow_end_time,flow_duration,"+\
            "flow_n_packets,fwd_n_packets,bwd_n_packets,"+\
            "flow_n_data_packets,fwd_n_data_packets,bwd_n_data_packets,"+\
            "flow_header_len_total,fwd_header_len_total,bwd_header_len_total,"+\
            "flow_packet_size_mean,flow_packet_size_std,flow_packet_size_max,"+\
            "flow_packet_size_min,fwd_packet_size_mean,fwd_packet_size_std,fwd_packet_size_max,fwd_packet_size_min,bwd_packet_size_mean,bwd_packet_size_std,bwd_packet_size_max,bwd_packet_size_min,"+\
            "flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec,"+\
            "flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,"+\
            "flow_packet_len_total,flow_packet_len_mean,flow_packet_len_std,flow_packet_len_var,flow_packet_len_max,flow_packet_len_min,"+\
            "fwd_packet_len_total,fwd_packet_len_mean,fwd_packet_len_std,fwd_packet_len_var,fwd_packet_len_max,fwd_packet_len_min,"+\
            "bwd_packet_len_total,bwd_packet_len_mean,bwd_packet_len_std,bwd_packet_len_var,bwd_packet_len_max,bwd_packet_len_min,"+\
            "flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,"+\
            "fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,"+\
            "bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,"+\
            "flow_df_count,flow_mf_count,flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count,"+\
            "fwd_df_count,fwd_mf_count,fwd_fin_count,fwd_syn_count,fwd_rst_count,fwd_psh_count,fwd_ack_count,fwd_urg_count,fwd_ece_count,fwd_cwr_count,"+\
            "bwd_df_count,bwd_mf_count,bwd_fin_count,bwd_syn_count,bwd_rst_count,bwd_psh_count,bwd_ack_count,bwd_urg_count,bwd_ece_count,bwd_cwr_count,"+\
            "label"
        
        tcp_flow_features_header_lst = tcp_flow_features_header_str.split(",")
        tcp_flow_feature_values_lst = \
            [flow_id,first_packet_time,last_packet_time,flow_duration,\
            flow_n_packets,fwd_n_packets,bwd_n_packets,\
            flow_n_data_packets,fwd_n_data_packets,bwd_n_data_packets,\
            flow_header_len_total,fwd_header_len_total,bwd_header_len_total,\
            flow_packet_size_mean,flow_packet_size_std,flow_packet_size_max,\
            flow_packet_size_min,fwd_packet_size_mean,fwd_packet_size_std,fwd_packet_size_max,fwd_packet_size_min,bwd_packet_size_mean,bwd_packet_size_std,bwd_packet_size_max,bwd_packet_size_min,\
            flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec,\
            flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,\
            flow_packet_len_total,flow_packet_len_mean,flow_packet_len_std,flow_packet_len_var,flow_packet_len_max,flow_packet_len_min,\
            fwd_packet_len_total,fwd_packet_len_mean,fwd_packet_len_std,fwd_packet_len_var,fwd_packet_len_max,fwd_packet_len_min,\
            bwd_packet_len_total,bwd_packet_len_mean,bwd_packet_len_std,bwd_packet_len_var,bwd_packet_len_max,bwd_packet_len_min,\
            flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,\
            fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,\
            bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,] +\
            flow_flag_counts +\
            fwd_flag_counts +\
            bwd_flag_counts +\
            [args.label]

        tcp_flow_features_generator = dict(zip(tcp_flow_features_header_lst, tcp_flow_feature_values_lst))

        yield tcp_flow_features_generator

'''
def calculate_talkers_features(flows, flow_ids):
    """Calculate and output talker features"""
    talker_ids = list()
    talkers = OrderedDict()
    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        src_ip = flow_id[0]
        dst_ip = flow_id[2]

        talker_id = (src_ip, dst_ip)

        # start and end times
        flow_start_time = curr_flow["flow_start_time"]
        flow_end_time = curr_flow["flow_end_time"]
        flow_duration = curr_flow["flow_duration"]

        try:
            talkers[talker_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }
        except KeyError:
            # talker_ids mantain the same order as flow_ids
            talker_ids.append(talker_id)
            talkers[talker_id] = OrderedDict()
            talkers[talker_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }


    for i, talker_id in enumerate(talker_ids):
        bwd_talker_id = (talker_id[1], talker_id[0])

        n_fwd_flows = len(talkers[talker_id])

        try:
            n_bwd_flows = len(talkers[bwd_talker_id])
        except KeyError:
            n_bwd_flows = 0

        #print("Talker %s ::: %s ::: %s" %(i,talker_id,talkers[talker_id]))

        # all flow durations of current talker
        flow_durations = []
        # first timestamps from forward and backward initiated talkers
        talker_first_times = []
        # last timestamps from forward and backward initiated talkers
        talker_last_times = []

        # FORWARDS
        for i, flow_id in enumerate(talkers[talker_id]):
            # flow durations
            curr_flow_duration = talkers[talker_id][flow_id]["flow_duration"]
            flow_durations.append(curr_flow_duration)
            # talker times
            # first flow
            if i==0:
                first_fwd_flow_start_time = talkers[talker_id][flow_id]["flow_start_time"]
                talker_first_times.append(first_fwd_flow_start_time)
            # last flow
            if i==n_fwd_flows-1:
                last_fwd_flow_start_time = talkers[talker_id][flow_id]["flow_end_time"]
                talker_last_times.append(last_fwd_flow_start_time)

        # BACKWARDS
        if bwd_talker_id in talkers:
            for i, flow_id in enumerate(talkers[bwd_talker_id]):
                # flow durations
                curr_flow_duration = talkers[bwd_talker_id][flow_id]["flow_duration"]
                flow_durations.append(curr_flow_duration)
                # talker times
                # first flow
                if i==0:
                    first_bwd_flow_start_time = talkers[bwd_talker_id][flow_id]["flow_start_time"]
                    talker_first_times.append(first_bwd_flow_start_time)
                # last flow
                if i==n_bwd_flows-1:
                    last_bwd_flow_start_time = talkers[bwd_talker_id][flow_id]["flow_end_time"]
                    talker_last_times.append(last_bwd_flow_start_time)

        talker_start_time = float(np.max(talker_first_times))
        talker_end_time = float(np.max(talker_last_times))
        talker_duration = talker_end_time - talker_start_time

        total_flow_duration = float(np.sum(flow_durations))
        mean_flow_duration = float(np.mean(flow_durations))
        std_flow_duration = float(np.std(flow_durations))
        var_flow_duration = float(np.var(flow_durations))
        max_flow_duration = float(np.max(flow_durations))
        min_flow_duration = float(np.min(flow_durations))

        fwd_flows_rate = 0 if total_flow_duration==0 else float(n_fwd_flows/total_flow_duration)
        bwd_flows_rate = 0 if total_flow_duration==0 else float(n_bwd_flows/total_flow_duration)

        talker_features_header = "talker_id,talker_start_time,talker_end_time,talker_duration,n_fwd_flows,n_bwd_flows,fwd_flows_rate,bwd_flows_rate," +\
        "total_flow_duration,mean_flow_duration,std_flow_duration,var_flow_duration,max_flow_duration,min_flow_duration," +\
        "label"
        talker_keys = talker_features_header.split(",")
        talker_values = \
            [talker_id, talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
            total_flow_duration, mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration,\
            args.label]

        talker_features_generator = dict(zip(talker_keys, talker_values))
        
        yield talker_features_generator

'''

'''
def calculate_hosts_features(talkers):
    """Calculate and output host features"""
    host_ids = list()
    hosts = OrderedDict()
    for talker_id in talkers:
        curr_talker = talkers[talker_id]
        src_ip = talker_id[0]
        dst_ip = talker_id[1]
        
        # start and end times
        #host_active_start_time = curr_talker["talker_start_time"]
        #host_active_end_time = curr_talker["talker_end_time"]
        talker_start_time = curr_talker["talker_start_time"]
        talker_end_time = curr_talker["talker_end_time"]
        talker_duration = curr_talker["talker_duration"]
        total_flow_duration = curr_talker["total_flow_duration"]

        # SOURCE
        try:
            hosts[src_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(src_ip)
            hosts[src_ip] = OrderedDict()
            hosts[src_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }

        # DESTINATION
        try:
            hosts[dst_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(dst_ip)
            hosts[dst_ip] = OrderedDict()
            hosts[dst_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }

    for i, host_id in enumerate(host_ids):
        n_talkers = len(hosts[host_id])
        rate_talkers = 0.01

        host_features_header = "host_id,n_talkers,rate_talkers,"+\
        "label"

        host_keys = host_features_header.split(",")
        host_values = \
            [host_id, n_talkers, rate_talkers,\
            args.label]

        host_features_generator = dict(zip(host_keys, host_values))
        
        yield host_features_generator
'''

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
    unique_uniflow_ids = parse_duplicate_uniflows(uniflow_ids)
    del(uniflow_ids)

    # ===================
    # NON-SEPARATED FLOWS
    # ===================
    flows,flow_ids = build_flows(uniflows, unique_uniflow_ids)
    del(uniflows)
    del(unique_uniflow_ids)

    # ===============================
    # TCP FLOWS (TCP Flag separation)
    # ===============================
    tcp_flows, tcp_flow_ids = build_tcpflows(flows, flow_ids)
    del(flows)
    del(flow_ids)

    # Note: At this point, flow_ids are ordered by the flow start time and the packets in each flow are internally ordered by their timestamp

    # Print some information about the selected flows
    if args.verbose:
        n_tcp_flow_packets=0
        for tcp_flow_id in tcp_flow_ids:
            n_tcp_flow_packets += len(tcp_flows[tcp_flow_id])
        print("########## TCP FLOWS (tcp flag separation) ##########")
        print("Number of packets included in the tcp flows:", n_tcp_flow_packets)
        print("Number of tcp flows:", len(tcp_flows))

    # Error case
    if len(tcp_flows)==0:
        print("This pcap doesn't have any communication that satisfies our flow definition. Abort.")
        exit()

    # this should be done before... need to refactor all this into smaller classes
    tcp_flow_features_generator = calculate_tcpflow_features(tcp_flows, tcp_flow_ids)
    del(tcp_flows)

    # REDO Flows dict with its features (drop packet info)
    flows = OrderedDict()
    for i, flow_features_dict in enumerate(tcp_flow_features_generator):
        curr_flow_id = flow_features_dict["flow_id"]
        flow_features_dict.pop(curr_flow_id, None)
        flows[curr_flow_id] = flow_features_dict
        print("Flow %s ::: %s" %(i, curr_flow_id))

    # Calculate Talker features
    """
    talker_features_generator = calculate_talkers_features(flows, flow_ids)
    # PARSE Flows to create Talkers
    talkers = OrderedDict()
    for i, talker_features_dict in enumerate(talker_features_generator):
        curr_talker_id = talker_features_dict["talker_id"]
        talker_features_dict.pop(curr_talker_id, None)
        talkers[curr_talker_id] = talker_features_dict
    """

    """
    # CALCULATE Host features
    host_features_generator = calculate_hosts_features(talkers)
    # PARSE Talkers to create Hosts
    hosts = OrderedDict()
    for i, host_features_dict in enumerate(host_features_generator):
        curr_host_id = host_features_dict["host_id"]
        host_features_dict.pop(curr_host_id, None)
        hosts[curr_host_id] = host_features_dict
    """

    # ---------------------------------------
    # INSERT hosts, talkers and hosts in DB
    # ---------------------------------------

    # HOSTS
    """
    hostid_sqlhostid = dict()
    for host_id in hosts:
        # host features
        n_talkers = hosts[host_id]["n_talkers"]
        rate_talkers = hosts[host_id]["rate_talkers"]

        ip_sql_repr = ipv4_octal_to_int(host_id)

        localdbconnector.safe_insert_query(
            "INSERT INTO Hosts (ip, n_talkers, rate_talkers) VALUES (%s, %s, %s)",
            (host_id, n_talkers, rate_talkers)
        )

        myresult = localdbconnector.select_query("SELECT id FROM Hosts WHERE ip = \"%s\"" %(host_id))
        sql_host_id = myresult[0][0]
        hostid_sqlhostid[host_id] = sql_host_id
    """

    # TALKERS
    """
    talkerid_sqltalkerid = dict()
    for talker_id in talkers:
        src_ip = talker_id[0]
        dst_ip = talker_id[1]

        # SQL Ids - Foreign Key Relations
        src_sql_host_id = hostid_sqlhostid[src_ip]
        dst_sql_host_id = hostid_sqlhostid[dst_ip]

        # talker features
        talker_start_time = talkers[talker_id]["talker_start_time"]
        talker_end_time = talkers[talker_id]["talker_end_time"]
        talker_duration = talkers[talker_id]["talker_duration"]
        n_fwd_flows = talkers[talker_id]["n_fwd_flows"]
        n_bwd_flows = talkers[talker_id]["n_bwd_flows"]
        fwd_flows_rate = talkers[talker_id]["fwd_flows_rate"]
        bwd_flows_rate = talkers[talker_id]["bwd_flows_rate"]
        total_flow_duration = talkers[talker_id]["total_flow_duration"]
        mean_flow_duration = talkers[talker_id]["mean_flow_duration"]
        std_flow_duration = talkers[talker_id]["std_flow_duration"]
        var_flow_duration = talkers[talker_id]["var_flow_duration"]
        max_flow_duration = talkers[talker_id]["max_flow_duration"]
        min_flow_duration = talkers[talker_id]["min_flow_duration"]

        src_ip_sql_repr = ipv4_octal_to_int(src_ip)
        dst_ip_sql_repr = ipv4_octal_to_int(dst_ip)
        talker_start_time = unix_time_millis_to_datetime(talker_start_time)
        talker_end_time = unix_time_millis_to_datetime(talker_end_time)

        localdbconnector.safe_insert_query(
            "INSERT INTO Talkers (src_ip, dst_ip, src_host_id, dst_host_id," + \
            "talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate, total_flow_duration," + \
            "mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)" + \
            " VALUES (%s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s)",
            (src_ip, dst_ip, src_sql_host_id, dst_sql_host_id, talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
            total_flow_duration, mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)
        )

        myresult = localdbconnector.select_query("SELECT id FROM Talkers WHERE src_ip = \"%s\" AND dst_ip = \"%s\"" %(src_ip, dst_ip))
        sql_talker_id = myresult[0][0]
        talkerid_sqltalkerid[talker_id] = sql_talker_id
    """

    # FLOWS
    for flow_id in flows:
        curr_flow = flows[flow_id]
        src_ip = flow_id[0]
        src_port = flow_id[1]
        dst_ip = flow_id[2]
        dst_port = flow_id[3]
        transport_protocol = flow_id[4]
        sep_counter = flow_id[5]

        # SQL Ids - Foreign Key Relations
        talker_id = (src_ip, dst_ip)
        sql_talker_id = talkerid_sqltalkerid[talker_id]

        # flow features
        flow_start_time = curr_flow["flow_start_time"]
        flow_end_time = curr_flow["flow_end_time"]
        flow_duration = curr_flow["flow_duration"]
        
        flow_n_packets = curr_flow["flow_n_packets"]
        fwd_n_packets = curr_flow["fwd_n_packets"]
        bwd_n_packets = curr_flow["bwd_n_packets"]

        flow_n_data_packets = curr_flow["flow_n_data_packets"]
        fwd_n_data_packets = curr_flow["fwd_n_data_packets"]
        bwd_n_data_packets = curr_flow["bwd_n_data_packets"]

        flow_header_len_total = curr_flow["flow_header_len_total"]
        fwd_header_len_total = curr_flow["fwd_header_len_total"]
        bwd_header_len_total = curr_flow["bwd_header_len_total"]

        flow_packet_size_mean = curr_flow["flow_packet_size_mean"]
        flow_packet_size_std = curr_flow["flow_packet_size_std"]
        flow_packet_size_max = curr_flow["flow_packet_size_max"]
        flow_packet_size_min = curr_flow["flow_packet_size_min"]
        
        fwd_packet_size_mean = curr_flow["fwd_packet_size_mean"]
        fwd_packet_size_std = curr_flow["fwd_packet_size_std"]
        fwd_packet_size_max = curr_flow["fwd_packet_size_max"]
        fwd_packet_size_min = curr_flow["fwd_packet_size_min"]

        bwd_packet_size_mean = curr_flow["bwd_packet_size_mean"]
        bwd_packet_size_std = curr_flow["bwd_packet_size_std"]
        bwd_packet_size_max = curr_flow["bwd_packet_size_max"]
        bwd_packet_size_min = curr_flow["bwd_packet_size_min"]

        flow_packets_per_sec = curr_flow["flow_packets_per_sec"]
        fwd_packets_per_sec = curr_flow["fwd_packets_per_sec"]
        bwd_packets_per_sec = curr_flow["bwd_packets_per_sec"]

        flow_bytes_per_sec = curr_flow["flow_bytes_per_sec"]
        fwd_bytes_per_sec = curr_flow["fwd_bytes_per_sec"]
        bwd_bytes_per_sec = curr_flow["bwd_bytes_per_sec"]

        flow_packet_len_total = curr_flow["flow_packet_len_total"]
        flow_packet_len_mean = curr_flow["flow_packet_len_mean"]
        flow_packet_len_std = curr_flow["flow_packet_len_std"]
        flow_packet_len_var = curr_flow["flow_packet_len_var"]
        flow_packet_len_max = curr_flow["flow_packet_len_max"]
        flow_packet_len_min = curr_flow["flow_packet_len_min"]

        fwd_packet_len_total = curr_flow["fwd_packet_len_total"]
        fwd_packet_len_mean = curr_flow["fwd_packet_len_mean"]
        fwd_packet_len_std = curr_flow["fwd_packet_len_std"]
        fwd_packet_len_var = curr_flow["fwd_packet_len_var"]
        fwd_packet_len_max = curr_flow["fwd_packet_len_max"]
        fwd_packet_len_min = curr_flow["fwd_packet_len_min"]

        bwd_packet_len_total = curr_flow["bwd_packet_len_total"]
        bwd_packet_len_mean = curr_flow["bwd_packet_len_mean"]
        bwd_packet_len_std = curr_flow["bwd_packet_len_std"]
        bwd_packet_len_var = curr_flow["bwd_packet_len_var"]
        bwd_packet_len_max = curr_flow["bwd_packet_len_max"]
        bwd_packet_len_min = curr_flow["bwd_packet_len_min"]

        flow_iat_total = curr_flow["flow_iat_total"]
        flow_iat_mean = curr_flow["flow_iat_mean"]
        flow_iat_std = curr_flow["flow_iat_std"]
        flow_iat_max = curr_flow["flow_iat_max"]
        flow_iat_min = curr_flow["flow_iat_min"]

        fwd_iat_total = curr_flow["fwd_iat_total"]
        fwd_iat_mean = curr_flow["fwd_iat_mean"]
        fwd_iat_std = curr_flow["fwd_iat_std"]
        fwd_iat_max = curr_flow["fwd_iat_max"]
        fwd_iat_min = curr_flow["fwd_iat_min"]
        
        bwd_iat_total = curr_flow["bwd_iat_total"]
        bwd_iat_mean = curr_flow["bwd_iat_mean"]
        bwd_iat_std = curr_flow["bwd_iat_std"]
        bwd_iat_max = curr_flow["bwd_iat_max"]
        bwd_iat_min = curr_flow["bwd_iat_min"]

        flow_df_count = curr_flow["flow_df_count"]
        flow_mf_count = curr_flow["flow_mf_count"]
        flow_fin_count = curr_flow["flow_fin_count"]
        flow_syn_count = curr_flow["flow_syn_count"]
        flow_rst_count = curr_flow["flow_rst_count"]
        flow_psh_count = curr_flow["flow_psh_count"]
        flow_ack_count = curr_flow["flow_ack_count"]
        flow_urg_count = curr_flow["flow_urg_count"]
        flow_ece_count = curr_flow["flow_ece_count"]
        flow_cwr_count = curr_flow["flow_cwr_count"]
        
        fwd_df_count = curr_flow["fwd_df_count"]
        fwd_mf_count = curr_flow["fwd_mf_count"]
        fwd_fin_count = curr_flow["fwd_fin_count"]
        fwd_syn_count = curr_flow["fwd_syn_count"]
        fwd_rst_count = curr_flow["fwd_rst_count"]
        fwd_psh_count = curr_flow["fwd_psh_count"]
        fwd_ack_count = curr_flow["fwd_ack_count"]
        fwd_urg_count = curr_flow["fwd_urg_count"]
        fwd_ece_count = curr_flow["fwd_ece_count"]
        fwd_cwr_count = curr_flow["fwd_cwr_count"]

        bwd_df_count = curr_flow["bwd_df_count"]
        bwd_mf_count = curr_flow["bwd_mf_count"]
        bwd_fin_count = curr_flow["bwd_fin_count"]
        bwd_syn_count = curr_flow["bwd_syn_count"]
        bwd_rst_count = curr_flow["bwd_rst_count"]
        bwd_psh_count = curr_flow["bwd_psh_count"]
        bwd_ack_count = curr_flow["bwd_ack_count"]
        bwd_urg_count = curr_flow["bwd_urg_count"]
        bwd_ece_count = curr_flow["bwd_ece_count"]
        bwd_cwr_count = curr_flow["bwd_cwr_count"]

        #src_ip_sql_repr = ipv4_octal_to_int(src_ip)
        #dst_ip_sql_repr = ipv4_octal_to_int(dst_ip)
        flow_start_time = unix_time_millis_to_datetime(flow_start_time)
        flow_end_time = unix_time_millis_to_datetime(flow_end_time)

        """
        # TODO: SQL ignores order when Keys are specified... I could have just used this method:
        # https://stackoverflow.com/questions/9336270/using-a-python-dict-for-a-sql-insert-statement
        localdbconnector.safe_insert_query(
            "INSERT INTO Flows (transport_protocol, src_ip, dst_ip, src_port, dst_port, sep_counter, talker_id," + \
            "flow_start_time, flow_end_time, flow_duration," + \
            "flow_n_packets,fwd_n_packets,bwd_n_packets," + \
            "flow_n_data_packets,fwd_n_data_packets,bwd_n_data_packets," + \
            "flow_header_len_total, fwd_header_len_total, bwd_header_len_total," + \
            "flow_packet_size_mean, flow_packet_size_std,flow_packet_size_max, flow_packet_size_min," + \
            "fwd_packet_size_mean, fwd_packet_size_std, fwd_packet_size_max, fwd_packet_size_min," + \
            "bwd_packet_size_mean, bwd_packet_size_std, bwd_packet_size_max, bwd_packet_size_min," + \
            "flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec," + \
            "flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec," + \
            "flow_packet_len_total,flow_packet_len_mean,flow_packet_len_std,flow_packet_len_var,flow_packet_len_max,flow_packet_len_min," + \
            "fwd_packet_len_total,fwd_packet_len_mean,fwd_packet_len_std,fwd_packet_len_var,fwd_packet_len_max,fwd_packet_len_min," + \
            "bwd_packet_len_total,bwd_packet_len_mean,bwd_packet_len_std,bwd_packet_len_var,bwd_packet_len_max,bwd_packet_len_min," + \
            "flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min," + \
            "fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min," + \
            "bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min," + \
            "flow_df_count,flow_mf_count,flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count," + \
            "fwd_df_count,fwd_mf_count,fwd_fin_count,fwd_syn_count,fwd_rst_count,fwd_psh_count,fwd_ack_count,fwd_urg_count,fwd_ece_count,fwd_cwr_count," + \
            "bwd_df_count,bwd_mf_count,bwd_fin_count,bwd_syn_count,bwd_rst_count,bwd_psh_count,bwd_ack_count,bwd_urg_count,bwd_ece_count,bwd_cwr_count)" + \
            " VALUES (" + \
            "%s, %s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s, %s," + \
            "%s, %s, %s, %s," + \
            "%s, %s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s" + \
            ")",
            (transport_protocol, src_ip, dst_ip, src_port, dst_port, sep_counter, sql_talker_id,\
            flow_start_time, flow_end_time, flow_duration,\
            flow_n_packets,fwd_n_packets,bwd_n_packets,\
            flow_n_data_packets,fwd_n_data_packets,bwd_n_data_packets,\
            flow_header_len_total, fwd_header_len_total, bwd_header_len_total,\
            flow_packet_size_mean, flow_packet_size_std,flow_packet_size_max, flow_packet_size_min,\
            fwd_packet_size_mean, fwd_packet_size_std, fwd_packet_size_max, fwd_packet_size_min,\
            bwd_packet_size_mean, bwd_packet_size_std, bwd_packet_size_max, bwd_packet_size_min,\
            flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec,\
            flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,\
            flow_packet_len_total,flow_packet_len_mean,flow_packet_len_std,flow_packet_len_var,flow_packet_len_max,flow_packet_len_min,\
            fwd_packet_len_total,fwd_packet_len_mean,fwd_packet_len_std,fwd_packet_len_var,fwd_packet_len_max,fwd_packet_len_min,\
            bwd_packet_len_total,bwd_packet_len_mean,bwd_packet_len_std,bwd_packet_len_var,bwd_packet_len_max,bwd_packet_len_min,\
            flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,\
            fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,\
            bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,\
            flow_df_count,flow_mf_count,flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count,\
            fwd_df_count,fwd_mf_count,fwd_fin_count,fwd_syn_count,fwd_rst_count,fwd_psh_count,fwd_ack_count,fwd_urg_count,fwd_ece_count,fwd_cwr_count,\
            bwd_df_count,bwd_mf_count,bwd_fin_count,bwd_syn_count,bwd_rst_count,bwd_psh_count,bwd_ack_count,bwd_urg_count,bwd_ece_count,bwd_cwr_count,
            )
        )
        """

    print("Dataset generated in \033[34m" + str(time.time() - start_time) + "\033[m seconds", file=sys.stderr)

if __name__ == "__main__":
    filenames = args.files
    for filename in filenames:
        print("Parsing " + filename + "...", file=sys.stderr)
        with open(filename, "rb") as f:
             generate_network_objets(f)
