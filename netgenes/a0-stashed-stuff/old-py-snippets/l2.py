# OTHER CONCEPTS
# L2 CONCEPTS
eth_type = eth.type
src_mac = mac_addr(eth.src)
dst_mac = mac_addr(eth.dst)
# L3 CONCEPTS
fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
# L4 CONCEPTS
# tcp seq number: not used to separate/select flows as the implemented rules alone seem to be working really fine
tcp_seq = transport_layer.seq