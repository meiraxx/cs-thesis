## Botnet Detection Engine
### Botnet Detection Engine (Backend)


PCAP Meter:
+ Parse PCAP file:
	+ osi-l3: IPv4/IPv6
	+ osi-l4: TCP/UDP
+ Calculate hosts, dialogues and flow features
+ Updated SQL database


### Botnet Detection Engine Dashboard (Frontend)

Net Manual Analysis:
+ Hosts
+ Dialogues
+ Flows

Net Behavioral Analysis:
+ PowerBI used to visualize data, used indicators and machine-learning model behavior

Trusted entities blacklists:
+ Each entity can view and choose to use other entities' blacklists


