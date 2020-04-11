# Standard
import datetime, time
import sys

# 3rdParty
try:
    import dpkt
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# Ours
from pylib.pyaux.utils import Colors, make_header_string
from pylib.pynet.protocol_utils import inet_to_str

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
    # when introducing mixed NetGenes (l3biflows/l4biflows/bitalkers/bihosts)
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
        ipv4_packet_genes = [str(datetime.datetime.utcfromtimestamp(timestamp)),\
        	ipv4_header_len, ipv4_data_len, ipv4_df_flag, ipv4_mf_flag]

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