# 1, 2 or 3 packets on a single biflow_id, in any circumstance, represents at most only one tcp flow
elif (flow_any_n_packets >= 1) and (flow_any_n_packets <= 3):
    rfc793_tcp_biflows[tmp_tcp_biflow_id] = curr_flow
    #if flow_any_n_packets!=2:
    #    print("?")
    #    print(str(tmp_tcp_biflow_id) + ":" + str(flow_any_n_packets))
    #    print(biflow_id_to_pcap_filter(tmp_tcp_biflow_id))
    rfc793_tcp_biflow_ids.append(tmp_tcp_biflow_id)