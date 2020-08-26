## NetGenes Elastic Search

Note: Filters do not include features, only additional information elements, since these are limited and well known. Filters using features are relevant for the detection of Programs, Events and Techniques, as well as Threats and Threat Classes.

### BiFlow
**BiFlow Filters:**  
- biflow filtering: {bihost_fwd_id: '147.32.84.165-TCP', bihost_bwd_id: '111.89.136.28-TCP', biflow_src_port: 50810, biflow_dst_port: 80}
- by UniTalker: "{unitalker_id: '147.32.84.165-111.89.136.28-TCP'}"
- by BiHost: "{$or: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}"
- by source host: "{bihost_fwd_id: '147.32.84.165-TCP'}"
- by destination host: "{bihost_bwd_id: '111.89.136.28-TCP'}"
- by source port: "{biflow_src_port: 50810}"
- by destination port: "{biflow_dst_port: 80}"
- source/forward UniTalker: {$and: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '111.89.136.28-TCP'}]}
- destination/backward UniTalker: {$and: [{bihost_fwd_id: '111.89.136.28-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}
- BiTalker filter: "{$or: [{$and: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '111.89.136.28-TCP'}]}, {$and: [{bihost_fwd_id: '111.89.136.28-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}]}"
- threat class filtering: {"Threat Class": "PortScan"}
- non-labeled filtering: {"Threat Class": {$not: {$regex: "PortScan"}}}

**BiFlow Sorts:**  
- 1: {biflow_any_first_packet_time: 1, biflow_any_last_packet_time: 1}
- 2: {bihost_fwd_id: 1, bihost_bwd_id: 1, biflow_any_first_packet_time: 1, biflow_any_last_packet_time: 1}
- 3: {bihost_fwd_id: 1, biflow_any_first_packet_time: 1, biflow_any_last_packet_time: 1}

**BiFlow Views:**  
- 1: {\_id: 0, biflow_id: 1, bihost_fwd_id: 1, bihost_bwd_id: 1, biflow_src_port: 1, biflow_dst_port: 1, "Threat Class": 1}
- 2: {\_id: 0, biflow_id: 1, bihost_fwd_id: 1, bihost_bwd_id: 1, biflow_src_port: 1, biflow_dst_port: 1, biflow_any_first_packet_time: 1, biflow_any_last_packet_time: 1, "Threat Class": 1}

## BiTalker
**BiTalker Filters:**  
- bitalker filtering: {$or: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}
- threat class filtering: {"Threat Class": {$regex:"PortScan"}}

**BiTalker Sorts:**  
- 1: {bitalker_any_first_biflow_initiation_time: 1, bitalker_any_last_biflow_termination_time: 1}
- 2: {"bihost_fwd_id": 1, biflow_any_first_packet_time: 1, biflow_any_last_packet_time: 1}

**BiTalker Views:**  
- 1: {\_id: 0, bitalker_id: 1, bihost_fwd_id: 1, bihost_bwd_id: 1, bitalker_any_first_biflow_initiation_time: 1, bitalker_any_last_biflow_termination_time: 1, "Threat Class": 1}

### BiHost
**BiHost Filters:**  
- bihost filtering: {bihost_id: '147.32.84.165-TCP'}
- hosts that only got contacted by other hosts: {bihost_fwd_n_bitalkers: 0, bihost_bwd_n_bitalkers: {$gte: 1}}
- hosts that only contacted other hosts: {bihost_bwd_n_bitalkers: 0, bihost_fwd_n_bitalkers: {$gte: 1}}
- threat class filtering: {"Threat Class": {$regex:"PortScan"}}

**BiHost Sorts:**  
- 1: {bihost_any_first_bitalker_initiation_time: 1, bihost_any_last_bitalker_termination_time: 1}

**BiHost Views:**  
- 1: {\_id: 0, bihost_id: 1, bihost_any_first_bitalker_initiation_time: 1, bihost_any_last_bitalker_termination_time: 1, bihost_any_n_bitalkers: 1, bihost_fwd_n_bitalkers: 1, bihost_bwd_n_bitalkers: 1, "Threat Class": 1}

