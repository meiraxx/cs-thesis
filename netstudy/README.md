## NetStudy Scripts
### Pre-conditions
Before using this tool, you should have preprocessed your raw network datasets (PCAP/PCAPNG) using the NetGene extractor tool, preferably in an environment with:
- A RAM that can handle those raw datasets
- A performant CPU

The resultant NetGenes are then usable by the NetHunter software for post-processing work.

### Description
NetStudy scripts will work on NetGenes-based datasets to:
- Create labeled (tool, threat class, threat) datasets based on:
	- Flows, Talkers, Hosts (Network Objects) - these are the labeled objects
	- Tool, Threat, Threat Class - these are used as the labeling criteria
- Apply and evaluate various classification techniques
