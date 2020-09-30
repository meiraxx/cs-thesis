# REDO Flows dict with its features (drop packet info)
flows = OrderedDict()
for i, flow_features_dict in enumerate(tcp_flow_features_generator):
    curr_flow_id = flow_features_dict["flow_id"]
    flow_features_dict.pop(curr_flow_id, None)
    flows[curr_flow_id] = flow_features_dict
    print("Flow %s ::: %s" %(i, curr_flow_id))

# ---------------------------------------
# INSERT flows, talkers and hosts in DB
# ---------------------------------------

# FLOWS
for flow_id in flows:
    curr_flow = flows[flow_id]
    src_ip = flow_id[0]
    src_port = flow_id[1]
    dst_ip = flow_id[2]
    dst_port = flow_id[3]
    transport_protocol = flow_id[4]
    inner_sep_counter = flow_id[5]

    # Relational DB Ids
    talker_id = (src_ip, dst_ip)
    #sql_talker_id = talkerid_sqltalkerid[talker_id]

    # Flow additional information
    flow_start_time = curr_flow["flow_start_time"]
    flow_end_time = curr_flow["flow_end_time"]

    # Flow features
    flow_duration = curr_flow["flow_duration"]
    
    flow_n_packets = curr_flow["flow_n_packets"]
    flow_fwd_n_packets = curr_flow["flow_fwd_n_packets"]
    flow_bwd_n_packets = curr_flow["flow_bwd_n_packets"]

    flow_n_data_packets = curr_flow["flow_n_data_packets"]
    flow_fwd_n_data_packets = curr_flow["flow_fwd_n_data_packets"]
    flow_bwd_n_data_packets = curr_flow["flow_bwd_n_data_packets"]

    flow_header_len_total = curr_flow["flow_header_len_total"]
    flow_fwd_header_len_total = curr_flow["flow_fwd_header_len_total"]
    flow_bwd_header_len_total = curr_flow["flow_bwd_header_len_total"]

    flow_packet_size_mean = curr_flow["flow_packet_size_mean"]
    flow_packet_size_std = curr_flow["flow_packet_size_std"]
    flow_packet_size_max = curr_flow["flow_packet_size_max"]
    flow_packet_size_min = curr_flow["flow_packet_size_min"]
    
    flow_fwd_packet_size_mean = curr_flow["flow_fwd_packet_size_mean"]
    flow_fwd_packet_size_std = curr_flow["flow_fwd_packet_size_std"]
    flow_fwd_packet_size_max = curr_flow["flow_fwd_packet_size_max"]
    flow_fwd_packet_size_min = curr_flow["flow_fwd_packet_size_min"]

    flow_bwd_packet_size_mean = curr_flow["flow_bwd_packet_size_mean"]
    flow_bwd_packet_size_std = curr_flow["flow_bwd_packet_size_std"]
    flow_bwd_packet_size_max = curr_flow["flow_bwd_packet_size_max"]
    flow_bwd_packet_size_min = curr_flow["flow_bwd_packet_size_min"]

    flow_packets_per_sec = curr_flow["flow_packets_per_sec"]
    flow_fwd_packets_per_sec = curr_flow["flow_fwd_packets_per_sec"]
    flow_bwd_packets_per_sec = curr_flow["flow_bwd_packets_per_sec"]

    flow_bytes_per_sec = curr_flow["flow_bytes_per_sec"]
    flow_fwd_bytes_per_sec = curr_flow["flow_fwd_bytes_per_sec"]
    flow_bwd_bytes_per_sec = curr_flow["flow_bwd_bytes_per_sec"]

    flow_packet_len_total = curr_flow["flow_packet_len_total"]
    flow_packet_len_mean = curr_flow["flow_packet_len_mean"]
    flow_packet_len_std = curr_flow["flow_packet_len_std"]
    flow_packet_len_var = curr_flow["flow_packet_len_var"]
    flow_packet_len_max = curr_flow["flow_packet_len_max"]
    flow_packet_len_min = curr_flow["flow_packet_len_min"]

    flow_fwd_packet_len_total = curr_flow["flow_fwd_packet_len_total"]
    flow_fwd_packet_len_mean = curr_flow["flow_fwd_packet_len_mean"]
    flow_fwd_packet_len_std = curr_flow["flow_fwd_packet_len_std"]
    flow_fwd_packet_len_var = curr_flow["flow_fwd_packet_len_var"]
    flow_fwd_packet_len_max = curr_flow["flow_fwd_packet_len_max"]
    flow_fwd_packet_len_min = curr_flow["flow_fwd_packet_len_min"]

    flow_bwd_packet_len_total = curr_flow["flow_bwd_packet_len_total"]
    flow_bwd_packet_len_mean = curr_flow["flow_bwd_packet_len_mean"]
    flow_bwd_packet_len_std = curr_flow["flow_bwd_packet_len_std"]
    flow_bwd_packet_len_var = curr_flow["flow_bwd_packet_len_var"]
    flow_bwd_packet_len_max = curr_flow["flow_bwd_packet_len_max"]
    flow_bwd_packet_len_min = curr_flow["flow_bwd_packet_len_min"]

    flow_iat_total = curr_flow["flow_iat_total"]
    flow_iat_mean = curr_flow["flow_iat_mean"]
    flow_iat_std = curr_flow["flow_iat_std"]
    flow_iat_max = curr_flow["flow_iat_max"]
    flow_iat_min = curr_flow["flow_iat_min"]

    flow_fwd_iat_total = curr_flow["flow_fwd_iat_total"]
    flow_fwd_iat_mean = curr_flow["flow_fwd_iat_mean"]
    flow_fwd_iat_std = curr_flow["flow_fwd_iat_std"]
    flow_fwd_iat_max = curr_flow["flow_fwd_iat_max"]
    flow_fwd_iat_min = curr_flow["flow_fwd_iat_min"]
    
    flow_bwd_iat_total = curr_flow["flow_bwd_iat_total"]
    flow_bwd_iat_mean = curr_flow["flow_bwd_iat_mean"]
    flow_bwd_iat_std = curr_flow["flow_bwd_iat_std"]
    flow_bwd_iat_max = curr_flow["flow_bwd_iat_max"]
    flow_bwd_iat_min = curr_flow["flow_bwd_iat_min"]

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
    
    flow_fwd_df_count = curr_flow["flow_fwd_df_count"]
    flow_fwd_mf_count = curr_flow["flow_fwd_mf_count"]
    flow_fwd_fin_count = curr_flow["flow_fwd_fin_count"]
    flow_fwd_syn_count = curr_flow["flow_fwd_syn_count"]
    flow_fwd_rst_count = curr_flow["flow_fwd_rst_count"]
    flow_fwd_psh_count = curr_flow["flow_fwd_psh_count"]
    flow_fwd_ack_count = curr_flow["flow_fwd_ack_count"]
    flow_fwd_urg_count = curr_flow["flow_fwd_urg_count"]
    flow_fwd_ece_count = curr_flow["flow_fwd_ece_count"]
    flow_fwd_cwr_count = curr_flow["flow_fwd_cwr_count"]

    flow_bwd_df_count = curr_flow["flow_bwd_df_count"]
    flow_bwd_mf_count = curr_flow["flow_bwd_mf_count"]
    flow_bwd_fin_count = curr_flow["flow_bwd_fin_count"]
    flow_bwd_syn_count = curr_flow["flow_bwd_syn_count"]
    flow_bwd_rst_count = curr_flow["flow_bwd_rst_count"]
    flow_bwd_psh_count = curr_flow["flow_bwd_psh_count"]
    flow_bwd_ack_count = curr_flow["flow_bwd_ack_count"]
    flow_bwd_urg_count = curr_flow["flow_bwd_urg_count"]
    flow_bwd_ece_count = curr_flow["flow_bwd_ece_count"]
    flow_bwd_cwr_count = curr_flow["flow_bwd_cwr_count"]

    flow_start_time = unix_time_millis_to_datetime(flow_start_time)
    flow_end_time = unix_time_millis_to_datetime(flow_end_time)
