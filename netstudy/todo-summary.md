## NetStudy
We will use NetStudy scripts to deal with any given dataset (represented by "XPTO"). Namely, we will deal with CICIDS-2017 and CTU-13 datasets.

### Summarized/Generic TODOS
**Finish thesis implementation:**
- Data labeling according to CIC and CTU-13
- Data analysis
- Data filtering for detections
- Metric calculations
- Portscan detection
- DOS detection
- Botnet detection

### Specific/Technical TODOS
**Create netgenes-labeled datasets (on XPTO):**
- Obtain labeled flows out of the XPTO dataset
- Parse two columns, xpto_flow_id and xpto_label, to a DataFrame
- Execute the mapping between xpto_flow_id and netgenes_flow_id
- Execute the mapping between xpto_label and labels based on three criteria - tools, threats and threat classes
- Starting with the processed non-labeled datasets, created processed labeled datasets divided in the three defined criteria(tools, threats and threat classes)

**Analyze netgenes-labeled datasets using:**
- Thought-out filters, based on domain knowledge
- Artificial Intelligence (optional)
- Metric calculations