## NetHunter Tool
### Pre-conditions
Before using this tool, you should have preprocessed your raw network datasets (PCAP/PCAPNG) using the NetGene extractor tool, preferably in an environment with:
- A RAM that can handle those raw datasets
- A performant CPU

The resultant NetGenes are then usable by the NetHunter software for post-processing work.

### Description
NetHunter has the objective of helping normal users work on NetGenes-based datasets by:
- Facilitating network-object visualization in unlabeled datasets
- Providing suggestions and controls for creating labeled datasets based on:
	- Flows, Talkers, Hosts (Network Objects) - these are the labeled objects
	- Tools, Threats, Threat Classes - these are used as the labeling criteria; the analysis of past instances of tools, threats and threat classes are used to build suggestions for any present analysis case
- Providing controls for using labeled datasets in the construction of:
	- Train Datasets
	- Test Datasets

## Disclaimer

This tool was never implemented due to time constraints.
