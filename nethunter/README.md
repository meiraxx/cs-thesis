## NetHunter Tool
### Pre-conditions
Before using this tool, you should have prepared your raw network datasets (PCAP/PCAPNG) by preprocessing them using NetMeter tool in an environment with:
- A RAM that can handle those datasets
- A performant CPU

The processed datasets are then usable by NetMeter for post-processing work.

### Description
This tool has the objective of helping users work on NetMeter-processed datasets by:
- Facilitating network-object visualization in unlabeled datasets
- Providing suggestions and controls for creating labeled datasets based on:
	- Network Object
	- Threat Class and Threat
- Providing controls for using labeled datasets in the construction of:
	- Train Datasets
	- Test Datasets
- ... (let's see how many time I have left to develop, but if so, will be able to also run and test classifiers, as well as extracting key features for each test-run)
