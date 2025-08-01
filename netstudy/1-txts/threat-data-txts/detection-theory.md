## Previous Work: Flow-based Program Detection; Flow-based Technique Detection
Network Objects: flows.  

Description:  
In our previous work, when we had less domain knowledge, we were experimenting with the CIC features (67 flow-only features, 46 flow-only time-independent features) and Machine Learning algorithms by randomly choosing programs which share the same threat classes (Port Scan, Denial of Service Attack, Brute Force Attack), extracting their flow features and directly using Machine Learning algorithms on top of those flow features. The theory was that, among those CIC features, all Threat Class-related programs would share common features which a Machine Learning model could use to detect any Threat Class-related program, even ones that had not be seen yet.  

We tried to separate the train datasets from the test datasets the most we could, organized by program, to ensure models wouldn't overfit to the data of one program only. We always included traffic from the same program in the testing dataset, but captured at different times, running on different machines and different networks. For Port Scan, the train datasets exclusively used nmap (in different modes) as the knowledge source and the test datasets included port scans used by nmap (different capture) and many other programs (Angry IP Scanner, UnicornScan, ncat, etc.).  

The first layer of our flow classification architecture, which was responsible for classifying traffic as one of three threat classes, had some trouble distinguishing between some threat classes. This inability to distinguish between threat classes is explained because those threat classes still shared a lot of common flow features among the considered flow features.  

On the other hand, the second layer of our flow classification architecture, which was responsible to separate threat-class traffic from benign traffic, was able to achieve good flow classification results for the Port Scan and Denial of Service threat classes and acceptable flow classification results for the Brute Force threat class. This ability to distinguish threat-class and benign traffic is explained because those threat classes, relatively to benign traffic, did not share many flow features, which allowed the ML models to more easily distinguish both types of traffic.  

Problem: The shared features of multiple programs may be related to a technique, however not all features are related to the intended technique we want to detect. For example, we might detect multiple Port Scans using flow features that are portrayed by many port scanners, such as packet inter-arrival time- or packet length- related features, however this doesn't necessarily mean that we captured the essence of what a Port Scan is, so this approach has two problems: (1) It won't detect all Port Scans; (2) It will detect traffic that is not Port Scan as a Port Scan. In fact, this is what happened in our previous work, where a TCP Syn Flood was found to be detected as a Port Scan instead of a Denial of Service Attack. This happened due to the Machine Learning algorithm not having enough visibility about many important features which did not exist at the time because they had not been implemented. Due to the previous problem, in this work, we now: (1) Value much more the features that we can come up with in the data preprocessing stage; (2) Analyze higher-level network objects above the Flow.

## This Work: Flow-based Program Detection; Flow-based Event Detection; Talker- and Host- based Technique Detection
Network Objects: flows, talkers and hosts.  
Notes:  
- Flow-based detection is very useful for program detection.
- Talker- and host- based detection should be ineffective for program detection because, since a system can use multiple programs at the same time, multiple unrelated flow sets can be created and taint the data at these higher levels. However, talker- and host- based detection is needed for a reliable technique detection.
- Program Detection can be a strong indicator of malicious activity.
- Event Detection can be a strong indicator of malicious activity.
- Technique Detection is a strong indicator of malicious activity.


### Flow-based Program Detection
Network Objects: flows.  

Description:  
One program may generate multiple flows. At the same time, multiple programs can generate similar flows, so one flow may be generated by multiple programs. This results in a "program \*<->\* flow" relationship. However, our flow definition is made of very specific features that are hardly reproducible in the same way by different programs using different server-client architectures and network stacks, so "program \*->1 flow" relationship can be safely disregarded for now. Rather, the focus should be on mapping multiple flows to one specific program ("program 1 ->\* flow" relationship). The objective of program detection is to eventually allow the detection of malicious activity, allowing to map programs to threats and threat classes. The "program \*<->\* threat" and "program \*<->\* threat class" relationships are ideal.  

In order to implement the "flow 1->\* program" relationship, we could use a set of fixed Flow definitions (for example, specifying threshold-based rules to which some flows may abide) to allow to practically map a flow to multiple programs and use it to filter down all possible program culprits even in the case where these programs use very similar network stacks and are able to generate similar flows. This task is not required for this work.  

### Talker-based and Host-based Technique Detection
Network Objects: talkers and hosts.  

Description:
From this point on, we will be working with flow sets rather than individual flows. The Talker and Host objects represent logically aggregated flow sets. The Talker object is the set of flows which can be aggregated by two joined three-sized tuples, creating the rule "(Source IP, Destination IP, protocol stack) || (Destination IP, Source IP, protocol stack)". The Host object is the set of flows which can be aggregated by two joined two-sized tuples, creating the rule "(Source IP, protocol stack) || (Destination IP, protocol stack)".  

For example, to reliably detect a Port Scan we need to look to the levels above the flow level, i.e. the talker and host levels, since these are the ones that can aggregate port-related features, which are one of the most essential features for Port Scan detection. Additionally, by aggregating other useful flow features (e.g. connection dropped) on those higher-context levels (e.g. total number of connections dropped), we can get a much higher probabilistic reliability when performing classification. The same principle applies to all techniques. This is the higher-level network objects Talker and Host.  

### All Object Relationships

*put data relation diagram here*