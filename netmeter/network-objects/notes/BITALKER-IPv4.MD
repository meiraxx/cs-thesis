# BiTalker
## Extended by: BiTalker-IPv4-L4, BiTalker-IPv4-TCP
## CURRENT NUMBER OF GENES
**83 BiTalker Genes:**  
- 11 Conceptual Features
- 72 Statistical Features

## IDENTIFIER
**bitalker_id (joined 3-tuple):**  
- (**source_ip**, destination_ip, protocol_stack)
- (source_ip, **destination_ip**, protocol_stack)

## ADDITIONAL INFORMATION
bihost_id
bitalker_any_first_biflow_initiation_time  
bitalker_any_last_biflow_termination_time  

## GENES
### Conceptual Features
**Time Features**  
bitalker_any_duration  

**Destination Port Features**  
bitalker_n_unique_dst_ports  

**BiFlow Number Features**  
bitalker_any_n_biflows  
bitalker_fwd_n_biflows  
bitalker_bwd_n_biflows  

**BiFlow Frequency Features**  
bitalker_any_biflows_per_sec  
bitalker_fwd_biflows_per_sec  
bitalker_bwd_biflows_per_sec  

**BiFlow Byte Frequency Features**  
bitalker_any_biflow_bytes_per_sec  
bitalker_fwd_biflow_bytes_per_sec  
bitalker_bwd_biflow_bytes_per_sec  

### Statistical Features
**IP Previous Statistical Features**  
Not added because it's an exaggeration at this level  

**Packet Features**  
bitalker_any_biflow_n_packets_total  
bitalker_any_biflow_n_packets_mean  
bitalker_any_biflow_n_packets_max  
bitalker_any_biflow_n_packets_min  
bitalker_any_biflow_n_packets_var  
bitalker_any_biflow_n_packets_std  

bitalker_fwd_biflow_n_packets_total  
bitalker_fwd_biflow_n_packets_mean  
bitalker_fwd_biflow_n_packets_max  
bitalker_fwd_biflow_n_packets_min  
bitalker_fwd_biflow_n_packets_var  
bitalker_fwd_biflow_n_packets_std  

bitalker_bwd_biflow_n_packets_total  
bitalker_bwd_biflow_n_packets_mean  
bitalker_bwd_biflow_n_packets_max  
bitalker_bwd_biflow_n_packets_min  
bitalker_bwd_biflow_n_packets_var  
bitalker_bwd_biflow_n_packets_std  

**Time Features**  
*BiFlow Durations*  
bitalker_any_biflow_duration_total  
bitalker_any_biflow_duration_mean  
bitalker_any_biflow_duration_std  
bitalker_any_biflow_duration_var  
bitalker_any_biflow_duration_max  
bitalker_any_biflow_duration_min  

bitalker_fwd_biflow_duration_total  
bitalker_fwd_biflow_duration_mean  
bitalker_fwd_biflow_duration_std  
bitalker_fwd_biflow_duration_var  
bitalker_fwd_biflow_duration_max  
bitalker_fwd_biflow_duration_min  

bitalker_bwd_biflow_duration_total  
bitalker_bwd_biflow_duration_mean  
bitalker_bwd_biflow_duration_std  
bitalker_bwd_biflow_duration_var  
bitalker_bwd_biflow_duration_max  
bitalker_bwd_biflow_duration_min  

*BiFlow Inter-Initiation Times*  
bitalker_any_biflow_iit_total  
bitalker_any_biflow_iit_mean  
bitalker_any_biflow_iit_std  
bitalker_any_biflow_iit_var  
bitalker_any_biflow_iit_max  
bitalker_any_biflow_iit_min  

bitalker_fwd_biflow_iit_total  
bitalker_fwd_biflow_iit_mean  
bitalker_fwd_biflow_iit_std  
bitalker_fwd_biflow_iit_var  
bitalker_fwd_biflow_iit_max  
bitalker_fwd_biflow_iit_min  

bitalker_bwd_biflow_iit_total  
bitalker_bwd_biflow_iit_mean  
bitalker_bwd_biflow_iit_std  
bitalker_bwd_biflow_iit_var  
bitalker_bwd_biflow_iit_max  
bitalker_bwd_biflow_iit_min  

*BiFlow Inter-Termination Times* (Note: careful to sort biflow termination times or use abs() function to have the right times)  
bitalker_any_biflow_itt_total  
bitalker_any_biflow_itt_mean  
bitalker_any_biflow_itt_std  
bitalker_any_biflow_itt_var  
bitalker_any_biflow_itt_max  
bitalker_any_biflow_itt_min  

bitalker_fwd_biflow_itt_total  
bitalker_fwd_biflow_itt_mean  
bitalker_fwd_biflow_itt_std  
bitalker_fwd_biflow_itt_var  
bitalker_fwd_biflow_itt_max  
bitalker_fwd_biflow_itt_min  

bitalker_bwd_biflow_itt_total  
bitalker_bwd_biflow_itt_mean  
bitalker_bwd_biflow_itt_std  
bitalker_bwd_biflow_itt_var  
bitalker_bwd_biflow_itt_max  
bitalker_bwd_biflow_itt_min  