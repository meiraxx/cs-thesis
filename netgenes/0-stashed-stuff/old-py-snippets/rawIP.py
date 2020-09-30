# [-] raw IPv4 packets containing filled IP protocol fields (icmp, igmp, udp, tcp, sctp)
# [!] NOTE: raw IP probes for any protocol are not checked because I haven't yet found a way to correctly
# separate them from unsupported protocols above the chosen IP protocol field's layer yet, however it
# should be done for the sake of rawIP-based scans
# (ipv4.p == 1 or ipv4.p == 2 or ipv4.p == 17 or ipv4.p == 6 or ipv4.p == 132) / 1 <= ipv4.p <= 255

if 1 <= ipv4.p <= 255:
    n_packets_eth_raw_ipv4_protocol_icmp_any += 1
    # [-] raw IP probes for IGMP
    if ipv4.p == 1:
        n_packets_eth_raw_ipv4_protocol_icmp += 1
    # [-] raw IP probes for IGMP
    elif ipv4.p == 2:
        n_packets_eth_raw_ipv4_protocol_igmp += 1
    # [-] raw IP probes for UDP
    elif ipv4.p == 17:
        n_packets_eth_raw_ipv4_protocol_udp += 1
    # [-] raw IP probes for TCP
    elif ipv4.p == 6:
        n_packets_eth_raw_ipv4_protocol_tcp += 1
    # [-] raw IP probes for SCTP
    elif ipv4.p == 132:
        n_packets_eth_raw_ipv4_protocol_sctp += 1
    else:
        n_packets_eth_raw_ipv4_protocol_others += 1
    continue