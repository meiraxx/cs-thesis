# More Features  
## Flow  
flag_rate = float(flag_count/n_pkts)  
fwd_flag_rate = float(fwd_flag_count/fwd_n_pkts)  
bwd_flag_rate = float(bwd_flag_count/bwd_n_pkts)  
connection_requested  
connection_established  
connection_refused  
connection_dropped  
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

(layer-7 protocol existence - ftp, ssh, telnet, http, https, irc, etc.; might introduce bias, introduce with care)  
port-21  
port-22  
port-23  
port-80  
port-443  
port-6697  


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
private_to_public  
private_to_private  
public_to_private  
public_to_public  

(n)
n_flows  

(type of flow)  
n_tcp_flows  
n_udp_flows  
n_icmp_flows  
n_fwd_tcp_flows  
n_fwd_udp_flows  
n_fwd_icmp_flows  
n_bwd_tcp_flows  
n_bwd_udp_flows  
n_bwd_icmp_flows  
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

public_address  
private_address  

dialogue_private_to_public_total  
dialogue_private_to_public_ratio  
dialogue_private_to_private_total  
dialogue_private_to_private_ratio  
dialogue_public_to_private_total  
dialogue_public_to_private_ratio  
dialogue_public_to_public_total  
dialogue_public_to_public_ratio  

>flow_active  
>flow_idle  