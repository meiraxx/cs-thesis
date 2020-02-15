# IPv4-FLOW
## Extended by: TCP-FLOW
## CURRENT NUMBER OF FEATURES
**121 Flow Features:**
- 13 Conceptual Features
- 108 Statistical Features

## IDENTIFIER
**flow_id (joined 6-tuple):**  
- (**source_ip**, **source_port**, destination_ip, destination_port, protocol_stack, inner_sep_counter)  
- (source_ip, source_port, **destination_ip**, **destination_port**, protocol_stack, inner_sep_counter)  

## ADDITIONAL INFORMATION
flow_any_first_packet_time  
flow_any_last_packet_time  

## FEATURES
### Conceptual Features
**Time Features**  
flow_any_duration  
flow_any_packets_per_sec  
flow_fwd_packets_per_sec  
flow_bwd_packets_per_sec  
flow_any_bytes_per_sec  
flow_fwd_bytes_per_sec  
flow_bwd_bytes_per_sec  

**Packet Number Features**  
flow_any_n_packets  
flow_fwd_n_packets  
flow_bwd_n_packets  
flow_any_n_data_packets  
flow_fwd_n_data_packets  
flow_bwd_n_data_packets  

### Statistical Features
**Joined IPv4 and L4 (TCP/UDP) Metadata Features**  
*Packet Header Lengths*  
flow_any_header_len_total  
flow_any_header_len_mean  
flow_any_header_len_std  
flow_any_header_len_var  
flow_any_header_len_max  
flow_any_header_len_min  
flow_fwd_header_len_total  
flow_fwd_header_len_mean  
flow_fwd_header_len_std  
flow_fwd_header_len_var  
flow_fwd_header_len_max  
flow_fwd_header_len_min  
flow_bwd_header_len_total  
flow_bwd_header_len_mean  
flow_bwd_header_len_std  
flow_bwd_header_len_var  
flow_bwd_header_len_max  
flow_bwd_header_len_min  

*Packet Sizes*  
flow_any_packet_size_total  
flow_any_packet_size_mean  
flow_any_packet_size_std  
flow_any_packet_size_var  
flow_any_packet_size_max  
flow_any_packet_size_min  
flow_fwd_packet_size_total  
flow_fwd_packet_size_mean  
flow_fwd_packet_size_std  
flow_fwd_packet_size_var  
flow_fwd_packet_size_max  
flow_fwd_packet_size_min  
flow_fwd_packet_size_total  
flow_bwd_packet_size_mean  
flow_bwd_packet_size_var  
flow_bwd_packet_size_std  
flow_bwd_packet_size_max  
flow_bwd_packet_size_min  

*Packet Lengths*  
flow_any_packet_len_total  
flow_any_packet_len_mean  
flow_any_packet_len_std  
flow_any_packet_len_var  
flow_any_packet_len_max  
flow_any_packet_len_min  
flow_fwd_packet_len_total  
flow_fwd_packet_len_mean  
flow_fwd_packet_len_std  
flow_fwd_packet_len_var  
flow_fwd_packet_len_max  
flow_fwd_packet_len_min  
flow_bwd_packet_len_total  
flow_bwd_packet_len_mean  
flow_bwd_packet_len_std  
flow_bwd_packet_len_var  
flow_bwd_packet_len_max  
flow_bwd_packet_len_min  

*IP Fragmentation Flags*  
flow_any_df_flags_total  
flow_any_df_flags_mean  
flow_any_df_flags_std  
flow_any_df_flags_var  
flow_any_df_flags_max  
flow_any_df_flags_min  
flow_any_mf_flags_total  
flow_any_mf_flags_mean  
flow_any_mf_flags_std  
flow_any_mf_flags_var  
flow_any_mf_flags_max  
flow_any_mf_flags_min  
flow_fwd_df_flags_total  
flow_fwd_df_flags_mean  
flow_fwd_df_flags_std  
flow_fwd_df_flags_var  
flow_fwd_df_flags_max  
flow_fwd_df_flags_min  
flow_fwd_mf_flags_total  
flow_fwd_mf_flags_mean  
flow_fwd_mf_flags_std  
flow_fwd_mf_flags_var  
flow_fwd_mf_flags_max  
flow_fwd_mf_flags_min  
flow_bwd_df_flags_total  
flow_bwd_df_flags_mean  
flow_bwd_df_flags_std  
flow_bwd_df_flags_var  
flow_bwd_df_flags_max  
flow_bwd_df_flags_min  
flow_bwd_mf_flags_total  
flow_bwd_mf_flags_mean  
flow_bwd_mf_flags_std  
flow_bwd_mf_flags_var  
flow_bwd_mf_flags_max  
flow_bwd_mf_flags_min  

**Time Features**  
flow_any_iat_total  
flow_any_iat_mean  
flow_any_iat_std  
flow_any_iat_var  
flow_any_iat_max  
flow_any_iat_min  
flow_fwd_iat_total  
flow_fwd_iat_mean  
flow_fwd_iat_std  
flow_fwd_iat_var  
flow_fwd_iat_max  
flow_fwd_iat_min  
flow_bwd_iat_total  
flow_bwd_iat_mean  
flow_bwd_iat_std  
flow_bwd_iat_var  
flow_bwd_iat_max  
flow_bwd_iat_min  
