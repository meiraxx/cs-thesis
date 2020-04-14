## Botnet Detection Engine  
### Botnet Detection Engine (Backend)  

**NetGenes Tool:**  
- Parse PCAP file:  
	- osi-l3: IPv4/IPv6
	- osi-l4: TCP/UDP
- Calculate hosts, dialogues and flow features
- Update SQL database continuously

**(Optional) Anomaly Detection Module:**  
- Implement detection algorithm for generic anomalous network behavior

*After finding the best botnet detection techniques (such as feature aggregation, time-window choice, and other techniques mentioned in the literature), the botnet detection module will be implemented by using those techniques applied to the datasets...*  

**Botnet Detection Module:**  
- In a given time-rate, re-read data from SQL database
- In each database re-read, re-test all the updated hosts, dialogues and flows for malicious indicators
- Save alerts in a database with a structured format, and save an IoC-filtered PCAP
- Continuously provide the front-end with relevant data for the user


### Botnet Detection Engine Dashboard (Frontend)

**Network Manual Analysis:**  
- Hosts
- Dialogues
- Flows

**Network Behavioral Analysis:**
- Visualize all data features tested
- Visualize only the most important indicators used by the ML model

**(Optional) Trusted entities' blacklists:**  
- Each entity can view and choose to use other entities' blacklists

**Alerts:**  
- List all alerts and provide search/sort capabilities, download IoCs and download IoC-filtered PCAP
