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
	- Network Object
	- Threat Class and Threat
- Providing controls for using labeled datasets in the construction of:
	- Train Datasets
	- Test Datasets
- ... (let's see how many time I have left to develop, but if so, will be able to also run and test classifiers, as well as extracting key features for each test-run)
