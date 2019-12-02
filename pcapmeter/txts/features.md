# More Features  
## Flow  
flag_rate = float(flag_count/n_pkts)  
fwd_flag_rate = float(fwd_flag_count/fwd_n_pkts)  
bwd_flag_rate = float(bwd_flag_count/bwd_n_pkts)  
connection_requested  
connection_established  
connection_refused  
connection_dropped  
direction ("external-to-internal", "internal-to-external", "internal-to-internal")  
flow_active_time_total  
flow_active_time_mean  
flow_active_time_min  
flow_active_time_max  
flow_active_time_var  
flow_active_time_std  

flow_idle_time_total  
flow_idle_time_mean  
flow_idle_time_min  
flow_idle_time_max  
flow_idle_time_var  
flow_idle_time_std  

## Dialogue  
(tcp-connections)  
fwd_n_connections_requested  
fwd_n_connections_established  
fwd_n_connections_refused  
fwd_n_connections_dropped  
bwd_n_connections_requested  
bwd_n_connections_established  
bwd_n_connections_refused  
bwd_n_connections_dropped  
  
(ports/tcp-connections)  
fwd_unique_port_n_connections_requested  
fwd_unique_port_n_connections_established  
fwd_unique_port_n_connections_refused  
fwd_unique_port_n_connections_dropped  
bwd_unique_port_n_connections_requested  
bwd_unique_port_n_connections_established  
bwd_unique_port_n_connections_refused  
bwd_unique_port_n_connections_dropped  
fwd_diff_port_n_connections_requested  
fwd_diff_port_n_connections_established  
fwd_diff_port_n_connections_refused  
fwd_diff_port_n_connections_dropped  
bwd_diff_port_n_connections_requested  
bwd_diff_port_n_connections_dropped  
bwd_diff_port_n_connections_established  
bwd_diff_port_n_connections_refused  

(ports)  
n_unique_dst_ports  
n_diff_dst_ports  

(flow inter-initiation time)  
flow_iit_total  
flow_iit_mean  
flow_iit_min  
flow_iit_max  
flow_iit_var  
flow_iit_std  

(direction)
direction_external_to_internal_total  
direction_external_to_internal_ratio  

direction_internal_to_external_total  
direction_internal_to_external_ratio  

direction_internal_to_internal_total  
direction_internal_to_internal_ratio  
>flow_active  
>flow_idle  

## Host  
Country  
Operating System  
Known LAN Host  
dialogue_iat_total  
dialogue_iat_mean  
dialogue_iat_min  
dialogue_iat_max  
dialogue_iat_var  
dialogue_iat_std  
>direction ("external-to-internal", "internal-to-external", "internal-to-internal")  
>flow_active  
>flow_idle  