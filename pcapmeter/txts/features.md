# More Features  
## Flow  
flow_flag_rate = float(flow_flag_count/flow_n_pkts)  
fwd_flag_rate = float(fwd_flag_count/fwd_n_pkts)  
bwd_flag_rate = float(bwd_flag_count/bwd_n_pkts)  

## Dialogue  
Connections Requested  
Connections Established  
Connections Refused/Dropped  
flow_iat_avg  
flow_iat_min  
flow_iat_max  
flow_iat_var  
flow_iat_std  

## Host  
dialogue_iat_avg  
dialogue_iat_min  
dialogue_iat_max  
dialogue_iat_var  
dialogue_iat_std  

Comments:  
(float_iat might be a good indicator of DDoS or portscan for example, but we'll leave that to machine learning)  
