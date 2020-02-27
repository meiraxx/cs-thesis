# IPv4-BiFlow
## Extended by: TCP-BiFlow
## CURRENT NUMBER OF GENES
**100 Biflow Genes:**
- 10 Conceptual Features
- 90 Statistical Features

## IDENTIFIER
**biflow_id (joined 6-tuple):**  
- (**source_ip**, **source_port**, destination_ip, destination_port, protocol_stack, inner_sep_counter)  
- (source_ip, source_port, **destination_ip**, **destination_port**, protocol_stack, inner_sep_counter)  

## ADDITIONAL INFORMATION
bitalker_id
biflow_any_first_packet_time  
biflow_any_last_packet_time  

## GENES
### Conceptual Features
**Time Features**  
biflow_any_duration  

**Packet Number Features**  
biflow_any_n_packets  
biflow_fwd_n_packets  
biflow_bwd_n_packets  

**Packet Frequency Features**  
biflow_any_packets_per_sec  
biflow_fwd_packets_per_sec  
biflow_bwd_packets_per_sec  

**Packet Byte Frequency Features**  
biflow_any_bytes_per_sec  
biflow_fwd_bytes_per_sec  
biflow_bwd_bytes_per_sec  

### Statistical Features
**Time Features**  
biflow_any_iat_total  
biflow_any_iat_mean  
biflow_any_iat_std  
biflow_any_iat_var  
biflow_any_iat_max  
biflow_any_iat_min  
biflow_fwd_iat_total  
biflow_fwd_iat_mean  
biflow_fwd_iat_std  
biflow_fwd_iat_var  
biflow_fwd_iat_max  
biflow_fwd_iat_min  
biflow_bwd_iat_total  
biflow_bwd_iat_mean  
biflow_bwd_iat_std  
biflow_bwd_iat_var  
biflow_bwd_iat_max  
biflow_bwd_iat_min  

**IPv4 Metadata Features**  
*Packet IPv4 Header Lengths*  
biflow_any_eth_ipv4_header_len_total  
biflow_any_eth_ipv4_header_len_mean  
biflow_any_eth_ipv4_header_len_std  
biflow_any_eth_ipv4_header_len_var  
biflow_any_eth_ipv4_header_len_max  
biflow_any_eth_ipv4_header_len_min  
biflow_fwd_eth_ipv4_header_len_total  
biflow_fwd_eth_ipv4_header_len_mean  
biflow_fwd_eth_ipv4_header_len_std  
biflow_fwd_eth_ipv4_header_len_var  
biflow_fwd_eth_ipv4_header_len_max  
biflow_fwd_eth_ipv4_header_len_min  
biflow_bwd_eth_ipv4_header_len_total  
biflow_bwd_eth_ipv4_header_len_mean  
biflow_bwd_eth_ipv4_header_len_std  
biflow_bwd_eth_ipv4_header_len_var  
biflow_bwd_eth_ipv4_header_len_max  
biflow_bwd_eth_ipv4_header_len_min  

*Packet IPv4 Data Lengths*  
biflow_any_eth_ipv4_data_len_total  
biflow_any_eth_ipv4_data_len_mean  
biflow_any_eth_ipv4_data_len_std  
biflow_any_eth_ipv4_data_len_var  
biflow_any_eth_ipv4_data_len_max  
biflow_any_eth_ipv4_data_len_min  
biflow_fwd_eth_ipv4_data_len_total  
biflow_fwd_eth_ipv4_data_len_mean  
biflow_fwd_eth_ipv4_data_len_std  
biflow_fwd_eth_ipv4_data_len_var  
biflow_fwd_eth_ipv4_data_len_max  
biflow_fwd_eth_ipv4_data_len_min  
biflow_bwd_eth_ipv4_data_len_total  
biflow_bwd_eth_ipv4_data_len_mean  
biflow_bwd_eth_ipv4_data_len_std  
biflow_bwd_eth_ipv4_data_len_var  
biflow_bwd_eth_ipv4_data_len_max  
biflow_bwd_eth_ipv4_data_len_min  

*IP Fragmentation Flags*  
biflow_any_eth_ip_df_flags_total  
biflow_any_eth_ip_df_flags_mean  
biflow_any_eth_ip_df_flags_std  
biflow_any_eth_ip_df_flags_var  
biflow_any_eth_ip_df_flags_max  
biflow_any_eth_ip_df_flags_min  
biflow_any_eth_ip_mf_flags_total  
biflow_any_eth_ip_mf_flags_mean  
biflow_any_eth_ip_mf_flags_std  
biflow_any_eth_ip_mf_flags_var  
biflow_any_eth_ip_mf_flags_max  
biflow_any_eth_ip_mf_flags_min  
biflow_fwd_eth_ip_df_flags_total  
biflow_fwd_eth_ip_df_flags_mean  
biflow_fwd_eth_ip_df_flags_std  
biflow_fwd_eth_ip_df_flags_var  
biflow_fwd_eth_ip_df_flags_max  
biflow_fwd_eth_ip_df_flags_min  
biflow_fwd_eth_ip_mf_flags_total  
biflow_fwd_eth_ip_mf_flags_mean  
biflow_fwd_eth_ip_mf_flags_std  
biflow_fwd_eth_ip_mf_flags_var  
biflow_fwd_eth_ip_mf_flags_max  
biflow_fwd_eth_ip_mf_flags_min  
biflow_bwd_eth_ip_df_flags_total  
biflow_bwd_eth_ip_df_flags_mean  
biflow_bwd_eth_ip_df_flags_std  
biflow_bwd_eth_ip_df_flags_var  
biflow_bwd_eth_ip_df_flags_max  
biflow_bwd_eth_ip_df_flags_min  
biflow_bwd_eth_ip_mf_flags_total  
biflow_bwd_eth_ip_mf_flags_mean  
biflow_bwd_eth_ip_mf_flags_std  
biflow_bwd_eth_ip_mf_flags_var  
biflow_bwd_eth_ip_mf_flags_max  
biflow_bwd_eth_ip_mf_flags_min  
