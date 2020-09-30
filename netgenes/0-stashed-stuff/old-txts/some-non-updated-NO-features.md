## More Features  
IMPORTANT: must consider biflow and uniflow usage advantages

### Flow  
()
flag_rate = float(flag_count/n_pkts)  
fwd_flag_rate = float(fwd_flag_count/fwd_n_pkts)  
bwd_flag_rate = float(bwd_flag_count/bwd_n_pkts)  

(biflow connection type)  
connection_requested  
connection_established  
connection_refused  
connection_redropped  

(tcp initiation type)  
full_duplex_initiation  
half_duplex_initiation  

(tcp termination type)  
termination_null  
termination_graceful  
termination_abort  

**The following biflow features have less probability of being added**  

(biflow activeness)  
biflow_active_time_total  
biflow_active_time_mean  
biflow_active_time_min  
biflow_active_time_max  
biflow_active_time_var  
biflow_active_time_std  

biflow_idle_time_total  
biflow_idle_time_mean  
biflow_idle_time_min  
biflow_idle_time_max  
biflow_idle_time_var  
biflow_idle_time_std  

(layer-7 protocol existence - ftp, ssh, telnet, http, https, irc, etc.; might introduce bias, introduce with care, consider protocol fingerprinting... except this might be hard to achieve for too many protocols right now. But we'll see. There are other priorities.)  
port-21  
port-22  
port-23  
port-80  
port-443  
port-6697  


### Talker  
(tcp-connections)  
fwd_n_connections_requested  
fwd_n_connections_established  
fwd_n_connections_refused  
fwd_n_connections_redropped  
bwd_n_connections_requested  
bwd_n_connections_established  
bwd_n_connections_refused  
bwd_n_connections_redropped  
  
(ports/tcp-connections)  
fwd_unique_port_n_connections_requested  
fwd_unique_port_n_connections_established  
fwd_unique_port_n_connections_refused  
fwd_unique_port_n_connections_redropped  
bwd_unique_port_n_connections_requested  
bwd_unique_port_n_connections_established  
bwd_unique_port_n_connections_refused  
bwd_unique_port_n_connections_redropped  
fwd_diff_port_n_connections_requested  
fwd_diff_port_n_connections_established  
fwd_diff_port_n_connections_refused  
fwd_diff_port_n_connections_redropped  
bwd_diff_port_n_connections_requested  
bwd_diff_port_n_connections_redropped  
bwd_diff_port_n_connections_established  
bwd_diff_port_n_connections_refused  

(ports)  
n_unique_dst_ports  
n_diff_dst_ports  

(biflow inter-initiation time)  
biflow_iit_total  
biflow_iit_mean  
biflow_iit_min  
biflow_iit_max  
biflow_iit_var  
biflow_iit_std  

(direction)  
private_to_public  
private_to_private  
public_to_private  
public_to_public  

(n)  
n_biflows  

(type of biflow)  
n_tcp_biflows  
n_udp_biflows  
n_icmp_biflows  
n_fwd_tcp_biflows  
n_fwd_udp_biflows  
n_fwd_icmp_biflows  
n_bwd_tcp_biflows  
n_bwd_udp_biflows  
n_bwd_icmp_biflows  
>biflow_active  
>biflow_idle  

## Host  
Country  
Operating System  
Known LAN Host  

bitalker_iat_total  
bitalker_iat_mean  
bitalker_iat_min  
bitalker_iat_max  
bitalker_iat_var  
bitalker_iat_std  

public_address  
private_address  

bitalker_private_to_public_total  
bitalker_private_to_public_ratio  
bitalker_private_to_private_total  
bitalker_private_to_private_ratio  
bitalker_public_to_private_total  
bitalker_public_to_private_ratio  
bitalker_public_to_public_total  
bitalker_public_to_public_ratio  

>biflow_active  
>biflow_idle  