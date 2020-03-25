## NetGenes Tool
### Description
This tool grabs a PCAP/PCAPNG file and extracts useful conceptual and statistical network-object features, called NetGenes. NetGenes refer to three different types of network objects:
- Flows (bidirectional - BiFlows)
- Talkers (bidirectional - BiTalkers)
- Hosts (unidirectional - UniHosts)

### What you can do with this tool
- Create new datasets with your capture files (the community thanks you if you label and share them)
- Analyze PCAP files manually: overview analysis, look for abnormal statistics
- Similarly to NetFlow extractors and others, the NetGenes extractor tool can be used as the basis network data extractor for other types of tools:
  - Network Intrusion Detection and Prevention System (NIDPS)
  - Security Information and Event Management (SIEM)
  - Threat Intelligence Platform (TIP)
  - Threat Hunting Platform (THP)
  - Etc.

### How to use it
```pip3 install -r requirements.txt```  
```python3 netgenes-tool.py```  

### Supported platforms
Any Linux or Windows platform with python >=3.6 should work.  
If you want to work with big files, it is advisable to increase your RAM as this tool saves pretty much everything on memory. It is also advisable that you have a performant CPU.

Enjoy :)
