# TALKER
## CURRENT NUMBER OF FEATURES
**140 Talker Features:**  
- 14 Conceptual Features
- 126 Statistical Features

## IDENTIFIER
**talker_id (joined 2-tuple):**  
- (**source_ip**, destination_ip)
- (source_ip, **destination_ip**)

## ADDITIONAL INFORMATION
talker_any_first_flow_time  
talker_any_last_flow_time  

## FEATURES
### Conceptual Features
**Time Features**  
talker_any_duration  
talker_any_flows_per_sec  
talker_fwd_flows_per_sec  
talker_bwd_flows_per_sec  
talker_any_flow_bytes_per_sec  
talker_fwd_flow_bytes_per_sec  
talker_bwd_flow_bytes_per_sec  

**Flow Number Features**  
talker_n_any_flows  
talker_n_fwd_flows  
talker_n_bwd_flows  

**TCP Flow Number Features**  
talker_n_any_tcp_flows  
talker_n_fwd_tcp_flows  
talker_n_bwd_tcp_flows  

**Destination Port Features**  
talker_n_unique_dst_ports  

### Statistical Features
**Data Features**  
None yet  

**Time Features**  
*Flow Durations*  
talker_any_flow_duration_total  
talker_any_flow_duration_mean  
talker_any_flow_duration_std  
talker_any_flow_duration_var  
talker_any_flow_duration_max  
talker_any_flow_duration_min  
talker_fwd_flow_duration_total  
talker_fwd_flow_duration_mean  
talker_fwd_flow_duration_std  
talker_fwd_flow_duration_var  
talker_fwd_flow_duration_max  
talker_fwd_flow_duration_min  
talker_bwd_flow_duration_total  
talker_bwd_flow_duration_mean  
talker_bwd_flow_duration_std  
talker_bwd_flow_duration_var  
talker_bwd_flow_duration_max  
talker_bwd_flow_duration_min  

*Flow Inter-Creation Times*  
talker_any_flow_ict_total  
talker_any_flow_ict_mean  
talker_any_flow_ict_std  
talker_any_flow_ict_var  
talker_any_flow_ict_max  
talker_any_flow_ict_min  
talker_fwd_flow_ict_total  
talker_fwd_flow_ict_mean  
talker_fwd_flow_ict_std  
talker_fwd_flow_ict_var  
talker_fwd_flow_ict_max  
talker_fwd_flow_ict_min  
talker_bwd_flow_ict_total  
talker_bwd_flow_ict_mean  
talker_bwd_flow_ict_std  
talker_bwd_flow_ict_var  
talker_bwd_flow_ict_max  
talker_bwd_flow_ict_min  

*Flow Inter-Initiation Times*  
talker_any_flow_iit_total  
talker_any_flow_iit_mean  
talker_any_flow_iit_std  
talker_any_flow_iit_var  
talker_any_flow_iit_max  
talker_any_flow_iit_min  
talker_fwd_flow_iit_total  
talker_fwd_flow_iit_mean  
talker_fwd_flow_iit_std  
talker_fwd_flow_iit_var  
talker_fwd_flow_iit_max  
talker_fwd_flow_iit_min  
talker_bwd_flow_iit_total  
talker_bwd_flow_iit_mean  
talker_bwd_flow_iit_std  
talker_bwd_flow_iit_var  
talker_bwd_flow_iit_max  
talker_bwd_flow_iit_min  

*Flow Inter-Termination Times*  
talker_any_flow_itt_total  
talker_any_flow_itt_mean  
talker_any_flow_itt_std  
talker_any_flow_itt_var  
talker_any_flow_itt_max  
talker_any_flow_itt_min  
talker_fwd_flow_itt_total  
talker_fwd_flow_itt_mean  
talker_fwd_flow_itt_std  
talker_fwd_flow_itt_var  
talker_fwd_flow_itt_max  
talker_fwd_flow_itt_min  
talker_bwd_flow_itt_total  
talker_bwd_flow_itt_mean  
talker_bwd_flow_itt_std  
talker_bwd_flow_itt_var  
talker_bwd_flow_itt_max  
talker_bwd_flow_itt_min  

**TCP Flow Features**  
*TCP Flow Connection Types*  
talker_tcpflow_connection_requested_total  
talker_tcpflow_connection_requested_mean  
talker_tcpflow_connection_requested_std  
talker_tcpflow_connection_requested_var  
talker_tcpflow_connection_requested_max  
talker_tcpflow_connection_requested_min  
talker_tcpflow_connection_established_total  
talker_tcpflow_connection_established_mean  
talker_tcpflow_connection_established_std  
talker_tcpflow_connection_established_var  
talker_tcpflow_connection_established_max  
talker_tcpflow_connection_established_min  
talker_tcpflow_connection_refused_total  
talker_tcpflow_connection_refused_mean  
talker_tcpflow_connection_refused_std  
talker_tcpflow_connection_refused_var  
talker_tcpflow_connection_refused_max  
talker_tcpflow_connection_refused_min  
talker_tcpflow_connection_dropped_total  
talker_tcpflow_connection_dropped_mean  
talker_tcpflow_connection_dropped_std  
talker_tcpflow_connection_dropped_var  
talker_tcpflow_connection_dropped_max  
talker_tcpflow_connection_dropped_min  

*TCP Flow Initiation Types*  
talker_tcpflow_full_duplex_initiation_total  
talker_tcpflow_full_duplex_initiation_mean  
talker_tcpflow_full_duplex_initiation_std  
talker_tcpflow_full_duplex_initiation_var  
talker_tcpflow_full_duplex_initiation_max  
talker_tcpflow_full_duplex_initiation_min  
talker_tcpflow_half_duplex_initiation_total  
talker_tcpflow_half_duplex_initiation_mean  
talker_tcpflow_half_duplex_initiation_std  
talker_tcpflow_half_duplex_initiation_var  
talker_tcpflow_half_duplex_initiation_max  
talker_tcpflow_half_duplex_initiation_min  

*TCP Flow Termination Types*  
talker_tcpflow_termination_null_total  
talker_tcpflow_termination_null_mean  
talker_tcpflow_termination_null_std  
talker_tcpflow_termination_null_var  
talker_tcpflow_termination_null_max  
talker_tcpflow_termination_null_min  
talker_tcpflow_termination_graceful_total  
talker_tcpflow_termination_graceful_mean  
talker_tcpflow_termination_graceful_std  
talker_tcpflow_termination_graceful_var  
talker_tcpflow_termination_graceful_max  
talker_tcpflow_termination_graceful_min  
talker_tcpflow_termination_abort_total  
talker_tcpflow_termination_abort_mean  
talker_tcpflow_termination_abort_std  
talker_tcpflow_termination_abort_var  
talker_tcpflow_termination_abort_max  
talker_tcpflow_termination_abort_min  

*TCP Flow Flags*  
None yet