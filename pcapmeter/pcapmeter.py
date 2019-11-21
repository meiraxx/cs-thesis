#!/usr/bin/env python3

"""
This script is meant to create a json file with a hierarchy "hosts" (ipX), "dialogues" (ipX-ipY) and "flows" (ipX-portA-ipY-portB),
while at the same time recording flow features, dialogue features and host features

AUTHORSHIP:
Joao Meira <joao.meira.cs@gmail.com>

"""

import dpkt
import numpy as np
import os, sys, time, datetime, socket, argparse
import ipaddress
import localdbconnector

from dpkt.compat import compat_ord
from collections import OrderedDict


# =====================
#     CLI OPTIONS
# =====================

op = argparse.ArgumentParser(description='PCAP flow parser')
op.add_argument('files', metavar='file', nargs='+', help='pcap file to parse flows from')
op.add_argument('-l', '--label', help="label all the flows", dest='label', default='unknown')
op.add_argument('-o', '--out-dir', help="output directory", dest='outdir', default='.' + os.sep)
op.add_argument('-c', '--check-transport-data-length', action='store_true', help='verbose output', dest='check_transport_data_length')
op.add_argument('-v', '--verbose', action='store_true', help='verbose output', dest='verbose')

args = op.parse_args()


datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
datetime_format2 = "%Y-%m-%d %H:%M:%S"
scale_factor = 0.001    # milliseconds --> seconds
packet_len_minimum = 64

def flow_id_to_dialogue_id(flow_id):
    splitted_flow_id = flow_id.split('-')
    return splitted_flow_id[0] + '-' + splitted_flow_id[2]

def gen_flow_str(flow_features):
    return flow_id_to_str(flow_features[0]) + ',' + ','.join(map(str,flow_features[1:])) + '\n'

def flow_id_to_str(flow_id):
    return '-'.join(map(str,flow_id))

def datetime_to_unix_time_millis(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000.0

def unix_time_millis_to_datetime(ms_timestamp):
    #try:
    dt = datetime.datetime.utcfromtimestamp(ms_timestamp/1000.0).strftime(datetime_format1)
    #except ValueError:
    #    dt = datetime.datetime.utcfromtimestamp(ms_timestamp/1000.0).strftime(datetime_format2)
    return dt

def mac_addr(address):
    '''Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    '''
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    '''Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    '''
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# PROCESS PCAP
def process_pcap(file):
    total_n_pkts = sum(1 for pkt in dpkt.pcap.Reader(file))
    file.seek(0)
    pcap = dpkt.pcap.Reader(file)
    n_pkts=0
    n_tcp=0
    n_udp=0
    packet_properties=[]

    localdbconnector.delete_all("Flows")
    localdbconnector.delete_all("Dialogues")
    localdbconnector.delete_all("Hosts")
    
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Check if the Ethernet data contains an IP packet. If it doesn't, ignore it
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        # Unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Pull out fragment information
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        transport_layer=ip.data
        transport_protocol_name=type(transport_layer).__name__

        if transport_protocol_name in ('TCP', 'UDP'):
            n_pkts+=1
            if transport_protocol_name=='TCP':
                n_tcp+=1
                fin_flag = ( transport_layer.flags & dpkt.tcp.TH_FIN ) != 0
                syn_flag = ( transport_layer.flags & dpkt.tcp.TH_SYN ) != 0
                rst_flag = ( transport_layer.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( transport_layer.flags & dpkt.tcp.TH_PUSH) != 0
                ack_flag = ( transport_layer.flags & dpkt.tcp.TH_ACK ) != 0
                urg_flag = ( transport_layer.flags & dpkt.tcp.TH_URG ) != 0
                ece_flag = ( transport_layer.flags & dpkt.tcp.TH_ECE ) != 0
                cwr_flag = ( transport_layer.flags & dpkt.tcp.TH_CWR ) != 0
                # tcp_seq = transport_layer.seq               # tcp seq number: not used to separate/select flows as the implemented rules alone seem to be working really fine
            elif transport_protocol_name=='UDP':
                n_udp+=1

            if transport_protocol_name=='TCP':
                ip_header_len = (ip.__hdr_len__ + len(ip.opts))
                transport_header_len = transport_layer.__hdr_len__ + len(transport_layer.opts)
                header_len = 14 + ip_header_len + transport_header_len    # header definition includes all except tcp.data (ip header, ip options, tcp header, tcp options)
                pkt_len = len(buf)

                # ethernet zero-byte padding until 64 bytes are reached
                if pkt_len>=packet_len_minimum:                                       # ethernet frame minimum size (minimum packet length)
                    pkt_size = pkt_len - header_len                                   # packet size (tcp data length)
                else:
                    eth_padding_bytes = pkt_len - header_len
                    # header len will ignore eth padding bytes
                    pkt_len = pkt_len - eth_padding_bytes
                    pkt_size = pkt_len - header_len                         # ethernet zero-byte padding until 64 bytes are reached

                if pkt_size!=len(transport_layer.data) and args.check_transport_data_length:
                    print("Error on packet no." + str(n_pkts) + ". Packet size should always correspond to tcp data length.", file=sys.stderr)
                    print(len(transport_layer.data),'!=',pkt_size, file=sys.stderr)
                    exit()

                src_ip = inet_to_str(ip.src)
                src_port = transport_layer.sport
                dst_ip = inet_to_str(ip.dst)
                dst_port = transport_layer.dport

                direction_id = (src_ip, src_port, dst_ip, dst_port, transport_protocol_name, 0)          # src ip, src port, dst ip, dst port, protocol, sep_counter
                packet_info = (direction_id,str(datetime.datetime.utcfromtimestamp(timestamp)),pkt_len,header_len,pkt_size,do_not_fragment,more_fragments,          \
                    fin_flag,syn_flag,rst_flag,psh_flag,ack_flag,urg_flag,ece_flag,cwr_flag) if transport_protocol_name=='TCP'\
                    else (direction_id,str(datetime.datetime.utcfromtimestamp(timestamp)),pkt_len,header_len,pkt_size,do_not_fragment,more_fragments)
                packet_properties.append(packet_info)

                src_ip_obj = ipaddress.IPv4Address(src_ip)
                dst_ip_obj = ipaddress.IPv4Address(dst_ip)
                src_ip_sql_repr = hex(int(src_ip_obj))[2:]
                dst_ip_sql_repr = hex(int(dst_ip_obj))[2:]
            # eventually_useful = (mac_addr(eth.src),mac_addr(eth.dst),eth.type,fragment_offset)

    if args.verbose:
        print('Number of UDP packets:',n_udp, file=sys.stderr)
        print('Number of TCP packets:',n_tcp, file=sys.stderr)
        print('Total number of packets:',n_pkts, file=sys.stderr)
    return packet_properties

def build_uniflows(packet_properties):
    #associate uniflow_ids to packets
    uniflows = dict()
    uniflow_ids = list()
    for propertie in packet_properties:
        uniflow_ids.append(propertie[0])
        if propertie[0] in uniflows:
            uniflows[propertie[0]].append(propertie)
        else:
            uniflows[propertie[0]]=[propertie]
    uniflow_ids=list(OrderedDict.fromkeys(uniflow_ids))             #remove duplicates mantaining order
    if args.verbose:
        print('Number of unidirectional flows (w/o flag separation):',len(uniflow_ids), file=sys.stderr)
    return uniflows,uniflow_ids

def parse_duplicates(uniflow_ids):
    #join unidirectional flows with their counterpart (flows/conversations)
    duplicates_parsed = list()
    for uniflow_id in uniflow_ids:
        try:
            custom_items = [ duplicates_parsed[i] for i in range(5) ]
        except IndexError:
            custom_items = list()
        if uniflow_id[0:-1] not in custom_items:
            duplicates_parsed.append(uniflow_id)
            duplicates_parsed.append((uniflow_id[2],uniflow_id[3],uniflow_id[0],uniflow_id[1],uniflow_id[4],uniflow_id[5]))
    return list(OrderedDict.fromkeys(duplicates_parsed))

def build_nsp_flows(uniflows, duplicates_parsed):
    #join unidirectional flow information into its bidirectional flow equivalent
    nsp_flows=dict()
    #non-separated flow ids (flows that haven't yet taken into account the begin/end flow flags)
    nsp_flow_ids=[]
    j=0
    while(j<len(duplicates_parsed)):
        nsp_flow_id = duplicates_parsed[j]
        duplicate_id = duplicates_parsed[j+1]
        # have in mind every flow_id in this list will constitute the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet
        nsp_flow_ids.append(nsp_flow_id)
        try:
            nsp_flows[nsp_flow_id] = uniflows[nsp_flow_id] + uniflows[duplicate_id]
        except KeyError:
            nsp_flows[nsp_flow_id] = uniflows[nsp_flow_id]
        j+=2
    if args.verbose:
        print('Number of bidirectional flows (w/o flag separation):',len(nsp_flow_ids), file=sys.stderr)
    return nsp_flows, nsp_flow_ids

def build_tcpflows(nsp_flows,nsp_flow_ids):
    # TODO: separate using tcp_seq too
    # fin,syn,rst,psh,ack,urg,ece,cwr (2,...,9)
    flows=dict()
    flow_ids=[]         # ordered flow keys (by flow start time)

    # create conventionally correct flows (conversations)
    for key in nsp_flow_ids:
        flow = nsp_flows[key]
        flow.sort(key=lambda x: x[1])       # sorting the packets in each flow by date-and-time
        if key[4]=="UDP": #udp flow
            flows[key] = flow
            flow_ids.append(key)
            continue
        flow_n_pkts = len(flow)

        if flow_n_pkts==0:
            raise ValueError('The flow can\'t have 0 packets.')
        elif flow_n_pkts in (1,2,3):     #1/2/3 pacotes num so nsp_flow_id perfazem no maximo 1 e 1 so flow
            flows[key] = flow
            flow_ids.append(key)
        else:
            i=0
            last_i=0
            flow_begin=False
            sep_counter=0
            while i<flow_n_pkts:
                fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1=flow[i][-8:]
                if i==flow_n_pkts-2:   # penultimate packet
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2=flow[i+1][-8:]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3=[False]*8
                elif i==flow_n_pkts-1: # last packet
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
                # the only rule used will be the half-duplex handshake rule because it is inclusive of the full-duplex handshake rule
                if r2:
                    flow_begin=True

                # we consider flows only the ones that start with a 2 or 3-way handshake (r1,r2)
                # the flow end conditions are r3 and r4, (fin,fin-ack,ack)/(rst,!rst,---), or if the packet is the last one of the existing communication
                if flow_begin:
                    if r3:
                        new_key=(key[0],key[1],key[2],key[3],key[4],key[5]+sep_counter)
                        flows[new_key] = flow[last_i:i+3]
                        flow_ids.append(new_key)
                        flow_begin=False
                        last_i=i+3
                        sep_counter+=1
                    elif r4 or i==flow_n_pkts-1:
                        new_key=(key[0],key[1],key[2],key[3],key[4],key[5]+sep_counter)
                        flows[new_key] = flow[last_i:i+1]
                        flow_ids.append(new_key)
                        flow_begin=False
                        last_i=i+1
                        sep_counter+=1
                i+=1
    return flows,flow_ids

def calculate_flows_features(flows,flow_ids):
    '''This function is a generator'''
    #flow_properties=[]
    for flow_id in flow_ids:
        flow_n_pkts = len(flows[flow_id])
        # [first packet][flow_id_index]
        direction_id = flows[flow_id][0][0]
        flow_iats = list()
        fwd_iats = list()
        bwd_iats = list()
        flow_pkt_lens = list()
        fwd_pkt_lens = list()
        bwd_pkt_lens = list()
        flow_header_lens = list()
        fwd_header_lens = list()
        bwd_header_lens = list()
        flow_pkt_sizes = list()
        fwd_pkt_sizes = list()
        bwd_pkt_sizes = list()
        flow_n_data_pkts = 0
        fwd_n_data_pkts = 0
        bwd_n_data_pkts = 0
        flow_flags = list()
        fwd_flags = list()
        bwd_flags = list()

        i = 0
        while i<flow_n_pkts:
            if i>=1:
                try:
                    first_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][i-1][1], datetime_format1))
                except ValueError:
                    first_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][i-1][1], datetime_format2))
                try:
                    second_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][i][1], datetime_format1))
                except ValueError:
                    second_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][i][1], datetime_format2))
                current_iat = scale_factor*(second_pkt_time - first_pkt_time)
                flow_iats.append(current_iat)
                if flows[flow_id][i-1][0]==direction_id:
                    fwd_iats.append(current_iat)
                else:
                    bwd_iats.append(current_iat)

            current_pkt_len = flows[flow_id][i][2]
            current_header_len = flows[flow_id][i][3]
            current_pkt_size = flows[flow_id][i][4]
            current_flags = flows[flow_id][i][-10:]

            flow_flags.append(current_flags)
            flow_pkt_lens.append(current_pkt_len)
            flow_header_lens.append(current_header_len)
            flow_pkt_sizes.append(current_pkt_size)

            if flows[flow_id][i][0]==direction_id:
                fwd_pkt_lens.append(current_pkt_len)
                fwd_header_lens.append(current_header_len)
                fwd_pkt_sizes.append(current_pkt_size)
                fwd_flags.append(current_flags)
                if current_header_len != current_pkt_len:
                    flow_n_data_pkts+=1
                    fwd_n_data_pkts+=1
            else:
                bwd_pkt_lens.append(current_pkt_len)
                bwd_header_lens.append(current_header_len)
                bwd_pkt_sizes.append(current_pkt_size)
                bwd_flags.append(current_flags)
                if current_header_len != current_pkt_len:
                    flow_n_data_pkts+=1
                    bwd_n_data_pkts+=1
            i+=1

        # number of packets (all times in seconds)
        # [first packet][timestamp_index]
        try:
            first_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][0][1], datetime_format1))
        except ValueError:
            first_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][0][1], datetime_format2))

        # [last packet][timestamp_index]
        try:
            last_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][flow_n_pkts-1][1], datetime_format1))
        except ValueError:
            last_pkt_time = datetime_to_unix_time_millis(datetime.datetime.strptime(flows[flow_id][flow_n_pkts-1][1], datetime_format2))
        flow_duration = scale_factor*(last_pkt_time - first_pkt_time)

        fwd_n_pkts = len(fwd_pkt_lens)
        bwd_n_pkts = len(bwd_pkt_lens)

        if flow_duration==0:
            flow_pkts_per_sec = fwd_pkts_per_sec = bwd_pkts_per_sec = 0
        else:
            flow_pkts_per_sec = flow_n_pkts/flow_duration
            fwd_pkts_per_sec = fwd_n_pkts/flow_duration
            bwd_pkts_per_sec = bwd_n_pkts/flow_duration

        # packet lengths
        flow_pkt_len_total = float(np.sum(flow_pkt_lens))
        flow_pkt_len_mean = float(np.mean(flow_pkt_lens))
        flow_pkt_len_std = float(np.std(flow_pkt_lens))
        flow_pkt_len_var = float(np.var(flow_pkt_lens))
        flow_pkt_len_max = float(np.max(flow_pkt_lens))
        flow_pkt_len_min = float(np.min(flow_pkt_lens))

        fwd_pkt_len_total = float(np.sum(fwd_pkt_lens))
        fwd_pkt_len_mean = float(np.mean(fwd_pkt_lens))
        fwd_pkt_len_std = float(np.std(fwd_pkt_lens))
        fwd_pkt_len_var = float(np.var(fwd_pkt_lens))
        fwd_pkt_len_max = float(np.max(fwd_pkt_lens))
        fwd_pkt_len_min = float(np.min(fwd_pkt_lens))

        if len(bwd_pkt_lens)!=0:
            bwd_pkt_len_total = float(np.sum(bwd_pkt_lens))
            bwd_pkt_len_mean = float(np.mean(bwd_pkt_lens))
            bwd_pkt_len_std = float(np.std(bwd_pkt_lens))
            bwd_pkt_len_var = float(np.var(bwd_pkt_lens))
            bwd_pkt_len_max = float(np.max(bwd_pkt_lens))
            bwd_pkt_len_min = float(np.min(bwd_pkt_lens))
        else:
            bwd_pkt_len_total = bwd_pkt_len_mean = bwd_pkt_len_std = bwd_pkt_len_var = bwd_pkt_len_max = bwd_pkt_len_min = 0

        # bytes per sec
        flow_bytes_per_sec = 0 if flow_duration==0 else float(flow_pkt_len_total/flow_duration)
        fwd_bytes_per_sec = 0 if flow_duration==0 else float(fwd_pkt_len_total/flow_duration)
        bwd_bytes_per_sec = 0 if flow_duration==0 else float(bwd_pkt_len_total/flow_duration)

        # header lengths (14 byte Ether header + ip header + tcp/udp header)
        flow_header_len_total = float(np.sum(flow_header_lens))
        fwd_header_len_total = float(np.sum(fwd_header_lens))
        bwd_header_len_total = float(np.sum(bwd_header_lens)) if len(bwd_header_lens)!=0 else 0

        # packet size
        flow_pkt_size_mean = float(np.mean(flow_pkt_sizes))
        flow_pkt_size_std = float(np.std(flow_pkt_sizes))
        flow_pkt_size_max = float(np.max(flow_pkt_sizes))
        flow_pkt_size_min = float(np.min(flow_pkt_sizes))

        fwd_pkt_size_mean = float(np.mean(fwd_pkt_sizes))
        fwd_pkt_size_std = float(np.std(fwd_pkt_sizes))
        fwd_pkt_size_max = float(np.max(fwd_pkt_sizes))
        fwd_pkt_size_min = float(np.min(fwd_pkt_sizes))

        if len(bwd_pkt_sizes)!=0:
            bwd_pkt_size_mean = float(np.mean(bwd_pkt_sizes))
            bwd_pkt_size_std = float(np.std(bwd_pkt_sizes))
            bwd_pkt_size_max = float(np.max(bwd_pkt_sizes))
            bwd_pkt_size_min = float(np.min(bwd_pkt_sizes))
        else:
            bwd_pkt_size_mean = bwd_pkt_size_std = bwd_pkt_size_max = bwd_pkt_size_min = 0


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

        # TODO: remove "flow_" from some fields, add "pkt_iat" instead of "flow_iat"
        flow_features_header = "flow_id,flow_start_time,flow_end_time,flow_duration,"+\
            "flow_n_pkts,fwd_n_pkts,bwd_n_pkts,"+\
            "flow_n_data_pkts,fwd_n_data_pkts,bwd_n_data_pkts,"+\
            "flow_header_len_total,fwd_header_len_total,bwd_header_len_total,"+\
            "flow_pkt_size_mean,flow_pkt_size_std,flow_pkt_size_max,"+\
            "flow_pkt_size_min,fwd_pkt_size_mean,fwd_pkt_size_std,fwd_pkt_size_max,fwd_pkt_size_min,bwd_pkt_size_mean,bwd_pkt_size_std,bwd_pkt_size_max,bwd_pkt_size_min,"+\
            "flow_pkts_per_sec,fwd_pkts_per_sec,bwd_pkts_per_sec,"+\
            "flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,"+\
            "flow_pkt_len_total,flow_pkt_len_mean,flow_pkt_len_std,flow_pkt_len_var,flow_pkt_len_max,flow_pkt_len_min,"+\
            "fwd_pkt_len_total,fwd_pkt_len_mean,fwd_pkt_len_std,fwd_pkt_len_var,fwd_pkt_len_max,fwd_pkt_len_min,"+\
            "bwd_pkt_len_total,bwd_pkt_len_mean,bwd_pkt_len_std,bwd_pkt_len_var,bwd_pkt_len_max,bwd_pkt_len_min,"+\
            "flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,"+\
            "fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,"+\
            "bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,"+\
            "flow_df_count,flow_mf_count,flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count,"+\
            "fwd_df_count,fwd_mf_count,fwd_fin_count,fwd_syn_count,fwd_rst_count,fwd_psh_count,fwd_ack_count,fwd_urg_count,fwd_ece_count,fwd_cwr_count,"+\
            "bwd_df_count,bwd_mf_count,bwd_fin_count,bwd_syn_count,bwd_rst_count,bwd_psh_count,bwd_ack_count,bwd_urg_count,bwd_ece_count,bwd_cwr_count,"+\
            "label"
        
        flow_keys = flow_features_header.split(",")

        flow_values = \
            [flow_id,first_pkt_time,last_pkt_time,flow_duration,\
            flow_n_pkts,fwd_n_pkts,bwd_n_pkts,\
            flow_n_data_pkts,fwd_n_data_pkts,bwd_n_data_pkts,\
            flow_header_len_total,fwd_header_len_total,bwd_header_len_total,\
            flow_pkt_size_mean,flow_pkt_size_std,flow_pkt_size_max,\
            flow_pkt_size_min,fwd_pkt_size_mean,fwd_pkt_size_std,fwd_pkt_size_max,fwd_pkt_size_min,bwd_pkt_size_mean,bwd_pkt_size_std,bwd_pkt_size_max,bwd_pkt_size_min,\
            flow_pkts_per_sec,fwd_pkts_per_sec,bwd_pkts_per_sec,\
            flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,\
            flow_pkt_len_total,flow_pkt_len_mean,flow_pkt_len_std,flow_pkt_len_var,flow_pkt_len_max,flow_pkt_len_min,\
            fwd_pkt_len_total,fwd_pkt_len_mean,fwd_pkt_len_std,fwd_pkt_len_var,fwd_pkt_len_max,fwd_pkt_len_min,\
            bwd_pkt_len_total,bwd_pkt_len_mean,bwd_pkt_len_std,bwd_pkt_len_var,bwd_pkt_len_max,bwd_pkt_len_min,\
            flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,\
            fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,\
            bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,] +\
            flow_flag_counts +\
            fwd_flag_counts +\
            bwd_flag_counts +\
            [args.label]

        flow_features_generator = dict(zip(flow_keys, flow_values))

        yield flow_features_generator

def ip_str_to_sql_repr(ip):
    # IP address Handling
    # TODO: handle IPv6
    ip_obj = ipaddress.IPv4Address(ip)
    ip_sql_repr = hex(int(ip_obj))[2:]
    return ip_sql_repr

def calculate_dialogues_features(flows, flow_ids):
    dialogue_ids = list()
    dialogues = OrderedDict()
    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        src_ip = flow_id[0]
        dst_ip = flow_id[2]

        dialogue_id = (src_ip, dst_ip)

        # start and end times
        flow_start_time = curr_flow["flow_start_time"]
        flow_end_time = curr_flow["flow_end_time"]
        flow_duration = curr_flow["flow_duration"]

        try:
            dialogues[dialogue_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }
        except KeyError:
            # dialogue_ids mantain the same order as flow_ids
            dialogue_ids.append(dialogue_id)
            dialogues[dialogue_id] = OrderedDict()
            dialogues[dialogue_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }


    for i, dialogue_id in enumerate(dialogue_ids):
        bwd_dialogue_id = (dialogue_id[1], dialogue_id[0])

        n_fwd_flows = len(dialogues[dialogue_id])

        try:
            n_bwd_flows = len(dialogues[bwd_dialogue_id])
        except KeyError:
            n_bwd_flows = 0

        #print("Dialogue %s ::: %s ::: %s" %(i,dialogue_id,dialogues[dialogue_id]))

        # all flow durations of current dialogue
        flow_durations = []
        # first timestamps from forward and backward initiated dialogues
        dialogue_first_times = []
        # last timestamps from forward and backward initiated dialogues
        dialogue_last_times = []

        # FORWARDS
        for i, flow_id in enumerate(dialogues[dialogue_id]):
            # flow durations
            curr_flow_duration = dialogues[dialogue_id][flow_id]["flow_duration"]
            flow_durations.append(curr_flow_duration)
            # dialogue times
            # first flow
            if i==0:
                first_fwd_flow_start_time = dialogues[dialogue_id][flow_id]["flow_start_time"]
                dialogue_first_times.append(first_fwd_flow_start_time)
            # last flow
            if i==n_fwd_flows-1:
                last_fwd_flow_start_time = dialogues[dialogue_id][flow_id]["flow_end_time"]
                dialogue_last_times.append(last_fwd_flow_start_time)

        # BACKWARDS
        if bwd_dialogue_id in dialogues:
            for i, flow_id in enumerate(dialogues[bwd_dialogue_id]):
                # flow durations
                curr_flow_duration = dialogues[bwd_dialogue_id][flow_id]["flow_duration"]
                flow_durations.append(curr_flow_duration)
                # dialogue times
                # first flow
                if i==0:
                    first_bwd_flow_start_time = dialogues[bwd_dialogue_id][flow_id]["flow_start_time"]
                    dialogue_first_times.append(first_bwd_flow_start_time)
                # last flow
                if i==n_bwd_flows-1:
                    last_bwd_flow_start_time = dialogues[bwd_dialogue_id][flow_id]["flow_end_time"]
                    dialogue_last_times.append(last_bwd_flow_start_time)

        dialogue_start_time = float(np.max(dialogue_first_times))
        dialogue_end_time = float(np.max(dialogue_last_times))
        dialogue_duration = dialogue_end_time - dialogue_start_time

        total_flow_duration = float(np.sum(flow_durations))
        mean_flow_duration = float(np.mean(flow_durations))
        std_flow_duration = float(np.std(flow_durations))
        var_flow_duration = float(np.var(flow_durations))
        max_flow_duration = float(np.max(flow_durations))
        min_flow_duration = float(np.min(flow_durations))

        fwd_flows_rate = 0 if total_flow_duration==0 else float(n_fwd_flows/total_flow_duration)
        bwd_flows_rate = 0 if total_flow_duration==0 else float(n_bwd_flows/total_flow_duration)

        dialogue_features_header = "dialogue_id,dialogue_start_time,dialogue_end_time,dialogue_duration,n_fwd_flows,n_bwd_flows,fwd_flows_rate,bwd_flows_rate," +\
        "total_flow_duration,mean_flow_duration,std_flow_duration,var_flow_duration,max_flow_duration,min_flow_duration," +\
        "label"
        dialogue_keys = dialogue_features_header.split(",")
        dialogue_values = \
            [dialogue_id, dialogue_start_time, dialogue_end_time, dialogue_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
            total_flow_duration, mean_flow_duration,std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration,\
            args.label]

        dialogue_features_generator = dict(zip(dialogue_keys, dialogue_values))
        
        yield dialogue_features_generator

def calculate_hosts_features(dialogues):
    host_ids = list()
    hosts = OrderedDict()
    for dialogue_id in dialogues:
        curr_dialogue = dialogues[dialogue_id]
        src_ip = dialogue_id[0]
        dst_ip = dialogue_id[1]
        
        # start and end times
        #host_active_start_time = curr_dialogue["dialogue_start_time"]
        #host_active_end_time = curr_dialogue["dialogue_end_time"]
        dialogue_start_time = curr_dialogue["dialogue_start_time"]
        dialogue_end_time = curr_dialogue["dialogue_end_time"]
        dialogue_duration = curr_dialogue["dialogue_duration"]
        total_flow_duration = curr_dialogue["total_flow_duration"]

        try:
            hosts[src_ip][dialogue_id] = \
            {
                "dialogue_start_time": dialogue_start_time,
                "dialogue_end_time": dialogue_end_time,
                "dialogue_duration": dialogue_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(src_ip)
            hosts[src_ip] = OrderedDict()
            hosts[src_ip][dialogue_id] = \
            {
                "dialogue_start_time": dialogue_start_time,
                "dialogue_end_time": dialogue_end_time,
                "dialogue_duration": dialogue_duration,
                "total_flow_duration": total_flow_duration,
            }

        try:
            hosts[dst_ip][dialogue_id] = \
            {
                "dialogue_start_time": dialogue_start_time,
                "dialogue_end_time": dialogue_end_time,
                "dialogue_duration": dialogue_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(dst_ip)
            hosts[dst_ip] = OrderedDict()
            hosts[dst_ip][dialogue_id] = \
            {
                "dialogue_start_time": dialogue_start_time,
                "dialogue_end_time": dialogue_end_time,
                "dialogue_duration": dialogue_duration,
                "total_flow_duration": total_flow_duration,
            }

    for i, host_id in enumerate(host_ids):
        n_dialogues = len(hosts[host_id])
        rate_dialogues = 0.01

        host_features_header = "host_id,n_dialogues,rate_dialogues,"+\
        "label"

        host_keys = host_features_header.split(",")
        host_values = \
            [host_id, n_dialogues, rate_dialogues,\
            args.label]

        host_features_generator = dict(zip(host_keys, host_values))
        
        yield host_features_generator

# PRINT FLOWS
def print_flows(file):
    start_time = time.time()

    packet_properties = process_pcap(file)
    uniflows,uniflow_ids = build_uniflows(packet_properties)
    del(packet_properties)
    duplicates_parsed = parse_duplicates(uniflow_ids)
    del(uniflow_ids)
    flows,flow_ids = build_nsp_flows(uniflows, duplicates_parsed)
    del(uniflows)
    del(duplicates_parsed)
    flows,flow_ids = build_tcpflows(flows, flow_ids)
    # At this point, flow_ids are ordered by the flow start time and the packets in each flow are internally ordered by their timestamp
    # Note: flow_ids only matter for flow order

    # Print some information about the selected flows
    if args.verbose:
        all_pkts=0
        for flow_id in flows:
            all_pkts+=len(flows[flow_id])
        print('Number of packets included in the flows\' analysis:', all_pkts, file=sys.stderr)
        print('Number of bidirectional flows (w/ flag separation):', len(flows), file=sys.stderr)

    # Error case
    if len(flows)==0:
        print('This pcap doesn\'t have any communication that satisfies our flow definition. Abort.', file=sys.stderr)
        return

    # this should be done before... need to refactor all this into smaller classes
    flow_features_generator = calculate_flows_features(flows, flow_ids)
    del(flows)

    # REDO Flows dict with its features (drop packet info)
    flows = OrderedDict()
    for i, flow_features_dict in enumerate(flow_features_generator):
        curr_flow_id = flow_features_dict["flow_id"]
        flow_features_dict.pop(curr_flow_id, None)
        flows[curr_flow_id] = flow_features_dict
        #print("Flow %s ::: %s" %(i, curr_flow_id))

    dialogue_features_generator = calculate_dialogues_features(flows, flow_ids)
    # PARSE Flows to create Dialogues
    dialogues = OrderedDict()
    for i, dialogue_features_dict in enumerate(dialogue_features_generator):
        curr_dialogue_id = dialogue_features_dict["dialogue_id"]
        dialogue_features_dict.pop(curr_dialogue_id, None)
        dialogues[curr_dialogue_id] = dialogue_features_dict

    host_features_generator = calculate_hosts_features(dialogues)
    # PARSE Dialogues to create Hosts
    hosts = OrderedDict()
    for i, host_features_dict in enumerate(host_features_generator):
        curr_host_id = host_features_dict["host_id"]
        host_features_dict.pop(curr_host_id, None)
        hosts[curr_host_id] = host_features_dict

    # ---------------------------------------
    # INSERT hosts, dialogues and hosts in DB
    # ---------------------------------------

    # HOSTS
    hostid_sqlhostid = dict()
    for host_id in hosts:
        # host features
        n_dialogues = hosts[host_id]["n_dialogues"]
        rate_dialogues = hosts[host_id]["rate_dialogues"]

        ip_sql_repr = ip_str_to_sql_repr(host_id)

        localdbconnector.safe_insert_query(
            "INSERT INTO Hosts (ip, n_dialogues, rate_dialogues) VALUES (%s, %s, %s)",
            (host_id, n_dialogues, rate_dialogues)
        )

        myresult = localdbconnector.select_query("SELECT id FROM Hosts WHERE ip = \"%s\"" %(host_id))
        sql_host_id = myresult[0][0]
        hostid_sqlhostid[host_id] = sql_host_id

    # DIALOGUES
    dialogueid_sqldialogueid = dict()
    for dialogue_id in dialogues:
        src_ip = dialogue_id[0]
        dst_ip = dialogue_id[1]

        # SQL Ids - Foreign Key Relations
        src_sql_host_id = hostid_sqlhostid[src_ip]
        dst_sql_host_id = hostid_sqlhostid[dst_ip]

        # dialogue features
        dialogue_start_time = dialogues[dialogue_id]["dialogue_start_time"]
        dialogue_end_time = dialogues[dialogue_id]["dialogue_end_time"]
        dialogue_duration = dialogues[dialogue_id]["dialogue_duration"]
        n_fwd_flows = dialogues[dialogue_id]["n_fwd_flows"]
        n_bwd_flows = dialogues[dialogue_id]["n_bwd_flows"]
        fwd_flows_rate = dialogues[dialogue_id]["fwd_flows_rate"]
        bwd_flows_rate = dialogues[dialogue_id]["bwd_flows_rate"]
        total_flow_duration = dialogues[dialogue_id]["total_flow_duration"]
        mean_flow_duration = dialogues[dialogue_id]["mean_flow_duration"]
        std_flow_duration = dialogues[dialogue_id]["std_flow_duration"]
        var_flow_duration = dialogues[dialogue_id]["var_flow_duration"]
        max_flow_duration = dialogues[dialogue_id]["max_flow_duration"]
        min_flow_duration = dialogues[dialogue_id]["min_flow_duration"]

        src_ip_sql_repr = ip_str_to_sql_repr(src_ip)
        dst_ip_sql_repr = ip_str_to_sql_repr(dst_ip)
        dialogue_start_time = unix_time_millis_to_datetime(dialogue_start_time)
        dialogue_end_time = unix_time_millis_to_datetime(dialogue_end_time)

        localdbconnector.safe_insert_query(
            "INSERT INTO Dialogues (src_ip, dst_ip, src_host_id, dst_host_id," + \
            "dialogue_start_time, dialogue_end_time, dialogue_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate, total_flow_duration," + \
            "mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)" + \
            " VALUES (%s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s, %s, %s, %s," + \
            "%s, %s, %s, %s, %s)",
            (src_ip, dst_ip, src_sql_host_id, dst_sql_host_id, dialogue_start_time, dialogue_end_time, dialogue_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
            total_flow_duration, mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)
        )

        myresult = localdbconnector.select_query("SELECT id FROM Dialogues WHERE src_ip = \"%s\" AND dst_ip = \"%s\"" %(src_ip, dst_ip))
        sql_dialogue_id = myresult[0][0]
        dialogueid_sqldialogueid[dialogue_id] = sql_dialogue_id

    # FLOWS
    for flow_id in flows:
        src_ip = flow_id[0]
        src_port = flow_id[1]
        dst_ip = flow_id[2]
        dst_port = flow_id[3]
        transport_protocol = flow_id[4]
        sep_counter = flow_id[5]

        # SQL Ids - Foreign Key Relations
        dialogue_id = (src_ip, dst_ip)
        sql_dialogue_id = dialogueid_sqldialogueid[dialogue_id]

        # flow features
        flow_start_time = flows[flow_id]["flow_start_time"]
        flow_end_time = flows[flow_id]["flow_end_time"]
        flow_duration = flows[flow_id]["flow_duration"]
        
        flow_n_pkts = flows[flow_id]["flow_n_pkts"]
        fwd_n_pkts = flows[flow_id]["fwd_n_pkts"]
        bwd_n_pkts = flows[flow_id]["bwd_n_pkts"]

        flow_n_data_pkts = flows[flow_id]["flow_n_data_pkts"]
        fwd_n_data_pkts = flows[flow_id]["fwd_n_data_pkts"]
        bwd_n_data_pkts = flows[flow_id]["bwd_n_data_pkts"]

        flow_header_len_total = flows[flow_id]["flow_header_len_total"]
        fwd_header_len_total = flows[flow_id]["fwd_header_len_total"]
        bwd_header_len_total = flows[flow_id]["bwd_header_len_total"]

        flow_pkt_size_mean = flows[flow_id]["flow_pkt_size_mean"]
        flow_pkt_size_std = flows[flow_id]["flow_pkt_size_std"]
        flow_pkt_size_max = flows[flow_id]["flow_pkt_size_max"]
        flow_pkt_size_min = flows[flow_id]["flow_pkt_size_min"]
        
        fwd_pkt_size_mean = flows[flow_id]["fwd_pkt_size_mean"]
        fwd_pkt_size_std = flows[flow_id]["fwd_pkt_size_std"]
        fwd_pkt_size_max = flows[flow_id]["fwd_pkt_size_max"]
        fwd_pkt_size_min = flows[flow_id]["fwd_pkt_size_min"]

        bwd_pkt_size_mean = flows[flow_id]["bwd_pkt_size_mean"]
        bwd_pkt_size_std = flows[flow_id]["bwd_pkt_size_std"]
        bwd_pkt_size_max = flows[flow_id]["bwd_pkt_size_max"]
        bwd_pkt_size_min = flows[flow_id]["bwd_pkt_size_min"]

        flow_pkts_per_sec = flows[flow_id]["flow_pkts_per_sec"]
        fwd_pkts_per_sec = flows[flow_id]["fwd_pkts_per_sec"]
        bwd_pkts_per_sec = flows[flow_id]["bwd_pkts_per_sec"]

        flow_bytes_per_sec = flows[flow_id]["flow_bytes_per_sec"]
        fwd_bytes_per_sec = flows[flow_id]["fwd_bytes_per_sec"]
        bwd_bytes_per_sec = flows[flow_id]["bwd_bytes_per_sec"]

        flow_pkt_len_total = flows[flow_id]["flow_pkt_len_total"]
        flow_pkt_len_mean = flows[flow_id]["flow_pkt_len_mean"]
        flow_pkt_len_std = flows[flow_id]["flow_pkt_len_std"]
        flow_pkt_len_var = flows[flow_id]["flow_pkt_len_var"]
        flow_pkt_len_max = flows[flow_id]["flow_pkt_len_max"]
        flow_pkt_len_min = flows[flow_id]["flow_pkt_len_min"]

        fwd_pkt_len_total = flows[flow_id]["fwd_pkt_len_total"]
        fwd_pkt_len_mean = flows[flow_id]["fwd_pkt_len_mean"]
        fwd_pkt_len_std = flows[flow_id]["fwd_pkt_len_std"]
        fwd_pkt_len_var = flows[flow_id]["fwd_pkt_len_var"]
        fwd_pkt_len_max = flows[flow_id]["fwd_pkt_len_max"]
        fwd_pkt_len_min = flows[flow_id]["fwd_pkt_len_min"]

        bwd_pkt_len_total = flows[flow_id]["bwd_pkt_len_total"]
        bwd_pkt_len_mean = flows[flow_id]["bwd_pkt_len_mean"]
        bwd_pkt_len_std = flows[flow_id]["bwd_pkt_len_std"]
        bwd_pkt_len_var = flows[flow_id]["bwd_pkt_len_var"]
        bwd_pkt_len_max = flows[flow_id]["bwd_pkt_len_max"]
        bwd_pkt_len_min = flows[flow_id]["bwd_pkt_len_min"]

        flow_iat_total = flows[flow_id]["flow_iat_total"]
        flow_iat_mean = flows[flow_id]["flow_iat_mean"]
        flow_iat_std = flows[flow_id]["flow_iat_std"]
        flow_iat_max = flows[flow_id]["flow_iat_max"]
        flow_iat_min = flows[flow_id]["flow_iat_min"]

        fwd_iat_total = flows[flow_id]["fwd_iat_total"]
        fwd_iat_mean = flows[flow_id]["fwd_iat_mean"]
        fwd_iat_std = flows[flow_id]["fwd_iat_std"]
        fwd_iat_max = flows[flow_id]["fwd_iat_max"]
        fwd_iat_min = flows[flow_id]["fwd_iat_min"]
        
        bwd_iat_total = flows[flow_id]["bwd_iat_total"]
        bwd_iat_mean = flows[flow_id]["bwd_iat_mean"]
        bwd_iat_std = flows[flow_id]["bwd_iat_std"]
        bwd_iat_max = flows[flow_id]["bwd_iat_max"]
        bwd_iat_min = flows[flow_id]["bwd_iat_min"]

        flow_df_count = flows[flow_id]["flow_df_count"]
        flow_mf_count = flows[flow_id]["flow_mf_count"]
        flow_fin_count = flows[flow_id]["flow_fin_count"]
        flow_syn_count = flows[flow_id]["flow_syn_count"]
        flow_rst_count = flows[flow_id]["flow_rst_count"]
        flow_psh_count = flows[flow_id]["flow_psh_count"]
        flow_ack_count = flows[flow_id]["flow_ack_count"]
        flow_urg_count = flows[flow_id]["flow_urg_count"]
        flow_ece_count = flows[flow_id]["flow_ece_count"]
        flow_cwr_count = flows[flow_id]["flow_cwr_count"]
        
        fwd_df_count = flows[flow_id]["fwd_df_count"]
        fwd_mf_count = flows[flow_id]["fwd_mf_count"]
        fwd_fin_count = flows[flow_id]["fwd_fin_count"]
        fwd_syn_count = flows[flow_id]["fwd_syn_count"]
        fwd_rst_count = flows[flow_id]["fwd_rst_count"]
        fwd_psh_count = flows[flow_id]["fwd_psh_count"]
        fwd_ack_count = flows[flow_id]["fwd_ack_count"]
        fwd_urg_count = flows[flow_id]["fwd_urg_count"]
        fwd_ece_count = flows[flow_id]["fwd_ece_count"]
        fwd_cwr_count = flows[flow_id]["fwd_cwr_count"]

        bwd_df_count = flows[flow_id]["bwd_df_count"]
        bwd_mf_count = flows[flow_id]["bwd_mf_count"]
        bwd_fin_count = flows[flow_id]["bwd_fin_count"]
        bwd_syn_count = flows[flow_id]["bwd_syn_count"]
        bwd_rst_count = flows[flow_id]["bwd_rst_count"]
        bwd_psh_count = flows[flow_id]["bwd_psh_count"]
        bwd_ack_count = flows[flow_id]["bwd_ack_count"]
        bwd_urg_count = flows[flow_id]["bwd_urg_count"]
        bwd_ece_count = flows[flow_id]["bwd_ece_count"]
        bwd_cwr_count = flows[flow_id]["bwd_cwr_count"]

        src_ip_sql_repr = ip_str_to_sql_repr(src_ip)
        dst_ip_sql_repr = ip_str_to_sql_repr(dst_ip)
        flow_start_time = unix_time_millis_to_datetime(flow_start_time)
        flow_end_time = unix_time_millis_to_datetime(flow_end_time)

        localdbconnector.safe_insert_query(
            "INSERT INTO Flows (transport_protocol, src_ip, dst_ip, src_port, dst_port, sep_counter, dialogue_id," + \
            "flow_start_time, flow_end_time, flow_duration," + \
            "flow_n_pkts,fwd_n_pkts,bwd_n_pkts," + \
            "flow_n_data_pkts,fwd_n_data_pkts,bwd_n_data_pkts," + \
            "flow_header_len_total, fwd_header_len_total, bwd_header_len_total," + \
            "flow_pkt_size_mean, flow_pkt_size_std,flow_pkt_size_max, flow_pkt_size_min," + \
            "fwd_pkt_size_mean, fwd_pkt_size_std, fwd_pkt_size_max, fwd_pkt_size_min," + \
            "bwd_pkt_size_mean, bwd_pkt_size_std, bwd_pkt_size_max, bwd_pkt_size_min," + \
            "flow_pkts_per_sec,fwd_pkts_per_sec,bwd_pkts_per_sec," + \
            "flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec," + \
            "flow_pkt_len_total,flow_pkt_len_mean,flow_pkt_len_std,flow_pkt_len_var,flow_pkt_len_max,flow_pkt_len_min," + \
            "fwd_pkt_len_total,fwd_pkt_len_mean,fwd_pkt_len_std,fwd_pkt_len_var,fwd_pkt_len_max,fwd_pkt_len_min," + \
            "bwd_pkt_len_total,bwd_pkt_len_mean,bwd_pkt_len_std,bwd_pkt_len_var,bwd_pkt_len_max,bwd_pkt_len_min," + \
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
            (transport_protocol, src_ip, dst_ip, src_port, dst_port, sep_counter, sql_dialogue_id,\
            flow_start_time, flow_end_time, flow_duration,\
            flow_n_pkts,fwd_n_pkts,bwd_n_pkts,\
            flow_n_data_pkts,fwd_n_data_pkts,bwd_n_data_pkts,\
            flow_header_len_total, fwd_header_len_total, bwd_header_len_total,\
            flow_pkt_size_mean, flow_pkt_size_std,flow_pkt_size_max, flow_pkt_size_min,\
            fwd_pkt_size_mean, fwd_pkt_size_std, fwd_pkt_size_max, fwd_pkt_size_min,\
            bwd_pkt_size_mean, bwd_pkt_size_std, bwd_pkt_size_max, bwd_pkt_size_min,\
            flow_pkts_per_sec,fwd_pkts_per_sec,bwd_pkts_per_sec,\
            flow_bytes_per_sec,fwd_bytes_per_sec,bwd_bytes_per_sec,\
            flow_pkt_len_total,flow_pkt_len_mean,flow_pkt_len_std,flow_pkt_len_var,flow_pkt_len_max,flow_pkt_len_min,\
            fwd_pkt_len_total,fwd_pkt_len_mean,fwd_pkt_len_std,fwd_pkt_len_var,fwd_pkt_len_max,fwd_pkt_len_min,\
            bwd_pkt_len_total,bwd_pkt_len_mean,bwd_pkt_len_std,bwd_pkt_len_var,bwd_pkt_len_max,bwd_pkt_len_min,\
            flow_iat_total,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,\
            fwd_iat_total,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,\
            bwd_iat_total,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,\
            flow_df_count,flow_mf_count,flow_fin_count,flow_syn_count,flow_rst_count,flow_psh_count,flow_ack_count,flow_urg_count,flow_ece_count,flow_cwr_count,\
            fwd_df_count,fwd_mf_count,fwd_fin_count,fwd_syn_count,fwd_rst_count,fwd_psh_count,fwd_ack_count,fwd_urg_count,fwd_ece_count,fwd_cwr_count,\
            bwd_df_count,bwd_mf_count,bwd_fin_count,bwd_syn_count,bwd_rst_count,bwd_psh_count,bwd_ack_count,bwd_urg_count,bwd_ece_count,bwd_cwr_count,
            )
        )

    print("Dataset generated in \033[34m" + str(time.time() - start_time) + "\033[m seconds", file=sys.stderr)

if __name__ == '__main__':
    filenames = args.files
    for filename in filenames:
        print("Parsing " + filename + "...", file=sys.stderr)
        with open(filename, 'rb') as f:
            print_flows(f)
