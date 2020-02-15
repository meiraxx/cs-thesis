# IPv4-TCP FLOW
## CURRENT NUMBER OF FEATURES
**153 Flow Features:**
- 9 Conceptual Flow Features
- 144 Statistical Flow Features

## FEATURES
### Conceptual Features
**TCP Flow Connection Type Features**  
flow_tcp_connection_requested  
flow_tcp_connection_established  
flow_tcp_connection_refused  
flow_tcp_connection_dropped  

**TCP Flow Initiation Type Features**  
flow_tcp_full_duplex_initiation  
flow_tcp_half_duplex_initiation  

**TCP Flow Termination Type Features**  
flow_tcp_termination_null  
flow_tcp_termination_graceful  
flow_tcp_termination_abort  

### Statistical Features
**TCP Flow Flags**  
flow_tcp_any_fin_flags_total  
flow_tcp_any_fin_flags_mean  
flow_tcp_any_fin_flags_std  
flow_tcp_any_fin_flags_var  
flow_tcp_any_fin_flags_max  
flow_tcp_any_fin_flags_min  
flow_tcp_any_syn_flags_total  
flow_tcp_any_syn_flags_mean  
flow_tcp_any_syn_flags_std  
flow_tcp_any_syn_flags_var  
flow_tcp_any_syn_flags_max  
flow_tcp_any_syn_flags_min  
flow_tcp_any_rst_flags_total  
flow_tcp_any_rst_flags_mean  
flow_tcp_any_rst_flags_std  
flow_tcp_any_rst_flags_var  
flow_tcp_any_rst_flags_max  
flow_tcp_any_rst_flags_min  
flow_tcp_any_psh_flags_total  
flow_tcp_any_psh_flags_mean  
flow_tcp_any_psh_flags_std  
flow_tcp_any_psh_flags_var  
flow_tcp_any_psh_flags_max  
flow_tcp_any_psh_flags_min  
flow_tcp_any_ack_flags_total  
flow_tcp_any_ack_flags_mean  
flow_tcp_any_ack_flags_std  
flow_tcp_any_ack_flags_var  
flow_tcp_any_ack_flags_max  
flow_tcp_any_ack_flags_min  
flow_tcp_any_urg_flags_total  
flow_tcp_any_urg_flags_mean  
flow_tcp_any_urg_flags_std  
flow_tcp_any_urg_flags_var  
flow_tcp_any_urg_flags_max  
flow_tcp_any_urg_flags_min  
flow_tcp_any_ece_flags_total  
flow_tcp_any_ece_flags_mean  
flow_tcp_any_ece_flags_std  
flow_tcp_any_ece_flags_var  
flow_tcp_any_ece_flags_max  
flow_tcp_any_ece_flags_min  
flow_tcp_any_cwr_flags_total  
flow_tcp_any_cwr_flags_mean  
flow_tcp_any_cwr_flags_std  
flow_tcp_any_cwr_flags_var  
flow_tcp_any_cwr_flags_max  
flow_tcp_any_cwr_flags_min  

flow_tcp_fwd_fin_flags_total  
flow_tcp_fwd_fin_flags_mean  
flow_tcp_fwd_fin_flags_std  
flow_tcp_fwd_fin_flags_var  
flow_tcp_fwd_fin_flags_max  
flow_tcp_fwd_fin_flags_min  
flow_tcp_fwd_syn_flags_total  
flow_tcp_fwd_syn_flags_mean  
flow_tcp_fwd_syn_flags_std  
flow_tcp_fwd_syn_flags_var  
flow_tcp_fwd_syn_flags_max  
flow_tcp_fwd_syn_flags_min  
flow_tcp_fwd_rst_flags_total  
flow_tcp_fwd_rst_flags_mean  
flow_tcp_fwd_rst_flags_std  
flow_tcp_fwd_rst_flags_var  
flow_tcp_fwd_rst_flags_max  
flow_tcp_fwd_rst_flags_min  
flow_tcp_fwd_psh_flags_total  
flow_tcp_fwd_psh_flags_mean  
flow_tcp_fwd_psh_flags_std  
flow_tcp_fwd_psh_flags_var  
flow_tcp_fwd_psh_flags_max  
flow_tcp_fwd_psh_flags_min  
flow_tcp_fwd_ack_flags_total  
flow_tcp_fwd_ack_flags_mean  
flow_tcp_fwd_ack_flags_std  
flow_tcp_fwd_ack_flags_var  
flow_tcp_fwd_ack_flags_max  
flow_tcp_fwd_ack_flags_min  
flow_tcp_fwd_urg_flags_total  
flow_tcp_fwd_urg_flags_mean  
flow_tcp_fwd_urg_flags_std  
flow_tcp_fwd_urg_flags_var  
flow_tcp_fwd_urg_flags_max  
flow_tcp_fwd_urg_flags_min  
flow_tcp_fwd_ece_flags_total  
flow_tcp_fwd_ece_flags_mean  
flow_tcp_fwd_ece_flags_std  
flow_tcp_fwd_ece_flags_var  
flow_tcp_fwd_ece_flags_max  
flow_tcp_fwd_ece_flags_min  
flow_tcp_fwd_cwr_flags_total  
flow_tcp_fwd_cwr_flags_mean  
flow_tcp_fwd_cwr_flags_std  
flow_tcp_fwd_cwr_flags_var  
flow_tcp_fwd_cwr_flags_max  
flow_tcp_fwd_cwr_flags_min  

flow_tcp_bwd_fin_flags_total  
flow_tcp_bwd_fin_flags_mean  
flow_tcp_bwd_fin_flags_std  
flow_tcp_bwd_fin_flags_var  
flow_tcp_bwd_fin_flags_max  
flow_tcp_bwd_fin_flags_min  
flow_tcp_bwd_syn_flags_total  
flow_tcp_bwd_syn_flags_mean  
flow_tcp_bwd_syn_flags_std  
flow_tcp_bwd_syn_flags_var  
flow_tcp_bwd_syn_flags_max  
flow_tcp_bwd_syn_flags_min  
flow_tcp_bwd_rst_flags_total  
flow_tcp_bwd_rst_flags_mean  
flow_tcp_bwd_rst_flags_std  
flow_tcp_bwd_rst_flags_var  
flow_tcp_bwd_rst_flags_max  
flow_tcp_bwd_rst_flags_min  
flow_tcp_bwd_psh_flags_total  
flow_tcp_bwd_psh_flags_mean  
flow_tcp_bwd_psh_flags_std  
flow_tcp_bwd_psh_flags_var  
flow_tcp_bwd_psh_flags_max  
flow_tcp_bwd_psh_flags_min  
flow_tcp_bwd_ack_flags_total  
flow_tcp_bwd_ack_flags_mean  
flow_tcp_bwd_ack_flags_std  
flow_tcp_bwd_ack_flags_var  
flow_tcp_bwd_ack_flags_max  
flow_tcp_bwd_ack_flags_min  
flow_tcp_bwd_urg_flags_total  
flow_tcp_bwd_urg_flags_mean  
flow_tcp_bwd_urg_flags_std  
flow_tcp_bwd_urg_flags_var  
flow_tcp_bwd_urg_flags_max  
flow_tcp_bwd_urg_flags_min  
flow_tcp_bwd_ece_flags_total  
flow_tcp_bwd_ece_flags_mean  
flow_tcp_bwd_ece_flags_std  
flow_tcp_bwd_ece_flags_var  
flow_tcp_bwd_ece_flags_max  
flow_tcp_bwd_ece_flags_min  
flow_tcp_bwd_cwr_flags_total  
flow_tcp_bwd_cwr_flags_mean  
flow_tcp_bwd_cwr_flags_std  
flow_tcp_bwd_cwr_flags_var  
flow_tcp_bwd_cwr_flags_max  
flow_tcp_bwd_cwr_flags_min  
