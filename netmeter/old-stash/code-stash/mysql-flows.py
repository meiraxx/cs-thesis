src_ip_sql_repr = ipv4_octal_to_int(src_ip)
dst_ip_sql_repr = ipv4_octal_to_int(dst_ip)

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