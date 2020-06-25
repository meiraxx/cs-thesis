## NetGenes Elastic Search

Note: Filters do not include features, only additional information elements, since these are limited and well known. Filters using features are relevant for the detection of Programs, Events and Techniques, as well as Threats and Threat Classes.

### BiFlow
**BiFlow Main Filters:**  
- by BiTalker: "{bitalker_id: '147.32.84.165-111.89.136.28-TCP'}"
- by BiHost: "{$or: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}"
- by source host: "{bihost_fwd_id: '147.32.84.165-TCP'}"
- by destination host: "{bihost_bwd_id: '111.89.136.28-TCP'}"
- by source port: "{biflow_src_port: 50810}"
- by destination port: "{biflow_dst_port: 80}"
- source/forward UniTalker: {$and: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '111.89.136.28-TCP'}]}
- destination/backward UniTalker: {$and: [{bihost_fwd_id: '111.89.136.28-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}
- alternative BiTalker filter: "{$or: [{$and: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '111.89.136.28-TCP'}]}, {$and: [{bihost_fwd_id: '111.89.136.28-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}]}"

**BiFlow Useful Filters:**  
- ...

**BiFlow Views:**  
- 1: {\_id: 0, biflow_id: 1, bitalker_id:1, bihost_fwd_id: 1, bihost_bwd_id: 1, biflow_src_port: 1, biflow_dst_port: 1}


## BiTalker
**BiTalker Filters:**  
- bitalker filtering: {$or: [{bihost_fwd_id: '147.32.84.165-TCP'}, {bihost_bwd_id: '147.32.84.165-TCP'}]}


### BiHost
**BiHost Filter:**  
- bihost filtering: {bihost_id: '147.32.84.165-TCP'}


**BiHost Useful Filters:**  
- hosts that only got contacted by other hosts: {bihost_fwd_n_bitalkers: 0, bihost_bwd_n_bitalkers: {$gte: 1}}
- hosts that only contacted other hosts: {bihost_bwd_n_bitalkers: 0, bihost_fwd_n_bitalkers: {$gte: 1}}

