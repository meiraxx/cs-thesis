"""
# ======================
# PLACEHOLDER: UDP FLOWS
# ======================
# TODO: UDP FLOWS
"""
"""
# =========
# TCP Flows
# =========

# ===================
# TCP Flag Separation
# ===================
tcp_flows, tcp_flow_ids = build_rfc793_tcp_biflows(flows, flow_ids)
del(flows)
del(flow_ids)
# NOTE: At this point, tcp_flow_ids are ordered by the flow start time and the packets in each flow are internally ordered by their timestamp
# Error case
if len(tcp_flows) == 0:
    print("This pcap doesn't have any communication that satisfies our TCP flow definition. Abort.", flush=True)
    sys.exit(1)
# Print some information about the built TCP flows
if args.verbose:
    n_preserved_packets = 0
    for tcp_flow_id in tcp_flow_ids:
        n_preserved_packets += len(tcp_flows[tcp_flow_id])
    print("########## IPv4-TCP FLOWS (Bidirectional; TCP flag separation) ##########", flush=True)
    print("IPv4-TCP flows:" + cterminal.colors.GREEN, str(len(tcp_flows)) + cterminal.colors.ENDC, flush=True)
    print("packets preserved in these flows:" + cterminal.colors.GREEN, str(n_preserved_packets) + cterminal.colors.ENDC, flush=True)

# this should be done before... need to refactor all this into smaller classes
#tcp_flow_genes_generator = calculate_eth_l3_flow_genes(tcp_flows, tcp_flow_ids)
#del(tcp_flows)
#output_eth_l3_flow_genes(tcp_flow_genes_generator, "csv")
"""