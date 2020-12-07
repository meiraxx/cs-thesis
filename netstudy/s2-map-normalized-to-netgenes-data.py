import os
import sys
import errno
import pandas
import numpy as np
import datetime
import re
#from random import randint
from pymongo import MongoClient, ASCENDING, DESCENDING
from utils import *

def map_original_to_netgenes_dataset(dataset_name, author_protocol_to_netgenes_protocol):
	"""
	Supported datasets: CIC-IDS-2017 and CTU-13
	Uses normalized author files to label netgenes unlabeled files, resulting in
	netgenes files with 3 extra fields: "Threat Class", "Threat" and "Tool".
	Due to misunderstandings between flow extraction tools, we will add a new field
	called "Mapping" to the BiFlow object, which will hold three possible values:
	"Standard", "Inverse" or "Null". Standard mapping means source IP, source port,
	destination IP and destination port are the same. Inverse mapping means source IP
	and source port were exchanged with destination IP and destination port. Null mapping
	("Null") means that the current netgenes flow did not exist in the dataset (not set here).
	"""

	# ------------
	# Author Files
	# ------------
	# Add "Author Flow ID" if needed, but only some datasets have it
	normalized_header_str = "L3-L4 Protocol,Source IP,Source Port,Destination IP,Destination Port,Author Label,Start Time"
	input_dir = os.path.join("s2-author-normalized-labeled-flows", dataset_name)
	
	# NetGenes MongoDb Client
	mongo_client = MongoClient("mongodb://localhost:27017")
	biflow_view = {
		"_id": 0,
		"biflow_id": 1,
		"bihost_fwd_id": 1,
		"bihost_bwd_id": 1,
		"biflow_src_port": 1,
		"biflow_dst_port": 1
	}

	for dname, dirs, files in os.walk(input_dir):
		for fname in files:
			# ------------
			# Author Files
			# ------------
			fpath = os.path.join(dname, fname)
			df = pandas.read_csv(fpath)

			# Select NetGenes MongoDb Database
			database_id = os.path.splitext(fname)[0]
			curr_db = mongo_client[database_id]
			print("[+] Mapping original dataset flows and labels to database (flows) '%s'" %(database_id))

			# Create index for flow filtering based on 5-tuple info (protocol excluded since dataset is
			# already separated in TCP and UDP collections) - deactivated to use timers as well
			"""
			biflow_compound_index = [
				("bihost_fwd_id", ASCENDING),
				("bihost_bwd_id", ASCENDING),
				("biflow_src_port", ASCENDING),
				("biflow_dst_port", ASCENDING)
			]
			curr_db["tcp_biflows"].create_index(biflow_compound_index)
			curr_db["udp_biflows"].create_index(biflow_compound_index)
			# the following indexes could be used if database searches are performed separately
			#curr_db["tcp_biflows"].create_index([("biflow_any_first_packet_time", ASCENDING), ("biflow_any_last_packet_time", ASCENDING)])
			#curr_db["udp_biflows"].create_index([("biflow_any_first_packet_time", ASCENDING), ("biflow_any_last_packet_time", ASCENDING)])
			"""
			# Create index for flow filtering based on first_packet_time and last_packet_time
			biflow_timed_biflow_compound_index = [
				("bihost_fwd_id", ASCENDING),
				("bihost_bwd_id", ASCENDING),
				("biflow_src_port", ASCENDING),
				("biflow_dst_port", ASCENDING),
				("biflow_any_first_packet_time", ASCENDING),
				("biflow_any_last_packet_time", ASCENDING)
			]
			curr_db["tcp_biflows"].create_index(biflow_timed_biflow_compound_index)
			curr_db["udp_biflows"].create_index(biflow_timed_biflow_compound_index)
			

			for index, row in df.iterrows():
				# Get parameters from DF
				author_protocol = str(row["L3-L4 Protocol"])
				src_ip = str(row["Source IP"])
				dst_ip = str(row["Destination IP"])
				src_port = int(row["Source Port"])
				dst_port = int(row["Destination Port"])
				start_time = row["Start Time"]
				splitted_start_time = re.split(" |/|:|\.", start_time)

				# Parse Timestamp
				second = 0
				millisecond = 0
				day, month, year, hour, minute = map(int, splitted_start_time[0:5])

				n_time_units = len(splitted_start_time)
				if (n_time_units < 5) or (n_time_units > 7):
					print("Error: unknown timestamp format '%s'"%(start_time))
					sys.exit(1)
				elif len(splitted_start_time)==6:
					second = int(splitted_start_time[5])
				elif len(splitted_start_time)==7:
					second = int(splitted_start_time[5])
					millisecond = int(splitted_start_time[6])
					
				
				# +3 hours, since e.g., 3:30 (pm) is equal to 18:30 in pcap data
				# Also, since PM and AM is not defined by CIC-IDS-2017 CSV files, we'll have to try both... :)
				am_hour = (hour+3)%12
				pm_hour = (hour+3)%12 + 12
				# Prepare filters to check if am_datetime is between packet start and end times OR
				# if pm_datetime is between packet start and end times. These filters are added to the
				# standard_biflow_filter and inverse_biflow_filter for checking
				# datetime with dates as strings filtering example:
				# in-between: {"biflow_any_first_packet_time": {"$gte": "2015-08-28 00:00:00", "$lt": "2015-08-29 00:00:00"}}
				# reverse in-between: {"biflow_any_first_packet_time": {"$lte": "2017-07-07 18:30:00"}, "biflow_any_last_packet_time": {"$gte": "2017-07-07 18:30:00"}}
				
				# NOTE: we'll add 1 minute to the start_time and subtract 1 minute from the last_time caps
				# to include all flows, since . This provides a 2-minute window in which 6-tuple
				# flows will be correctly captured. This 2-minute window is provided because CIC-IDS-2017
				# only provides accuracy at the level of the minute in all of its week-days, except for
				# Monday. This causes, for example 12:00 to not be in an interval between 12:45:12.345678
				# and 12:46:00.000001. For exampele, in Friday, which has 347994 records, only 36967 were
				# being mapped without this window and, with it, 347624 flows were labeled.
				# It's worth remarking again that we need to consider the time because CIC-IDS-2017 flow-ids
				# are not enough for us to separate all labels in their due place. Without this times, we
				# would have just assigned all 6-tuple flows the last generated 5-tuple flow label that the
				# script had found, so our label mapping wouldn't be accurate. Now, we can use this to correctly
				# separate all the threat classes into their CSV.
				# Mapping TCP Flows
				# Mapped/Labeled: '{$or: [{Mapping: "Inverse"}, {Mapping: "Standard"}]}'
				# Unmapped/Unlabeled: '{$nor: [{Mapping: "Inverse"}, {Mapping: "Standard"}]}'
				
				# No WINDOW: caused the same number of labeled/unlabeled flows as the 10-minute window filter,
				# however a lot of flows were misslabeled
				# Week Day | N_Labeled_TCP_Flows | N_Unlabeled_TCP_Flows | N_Labeled_UDP_Flows | N_Unlabeled_UDP_Flows
				# Monday | 132208 | 10 | ... | ...
				# Tuesday | 109133 | 31 | ... | ...
				# Wednesday | 273836 | 22 | ... | ...
				# Thursday | 167808 | 95 | ... | ...
				# Friday | 347821 | 173 | ... | ...
				# NOTE: Friday flows improved due to 2 flows: "192.229.163.213-443-192.168.10.16-51046-TCP-1"
				# "192.229.163.213-443-192.168.10.16-51048-TCP-1" now being caught. The rest of the flows
				# have the flow separation counter set to 0 and do not exist in the provided CIC-IDS-2017
				# CSV datasets.

				# USING 2-MINUTE Window (start_time - 1 minute > target_time > end_time + 1 minute )
				# Week Day | N_Labeled_TCP_Flows | N_Unlabeled_TCP_Flows | N_Labeled_UDP_Flows | N_Unlabeled_UDP_Flows
				# Monday | 132208 | 10 | ... | ...
				# Tuesday | 109105 | 59 | ... | ...
				# Wednesday | 273678 | 180 | ... | ...
				# Thursday | 167803 | 100 | ... | ...
				# Friday | 347624 | 370 | ... | ...
				# NOTE: The following results are better in terms of catching more CIC-IDS-2017 flows,
				# but if multiple 6-tuple flows with the same 5-tuple flow are too close to each other in
				# terms of timing, both flows will keep the last flow's label.

				# USING 10-MINUTE Window (start_time - 5 minutes > target_time > end_time + 5 minutes )
				# Week Day | N_Labeled_TCP_Flows | N_Unlabeled_TCP_Flows | N_Labeled_UDP_Flows | N_Unlabeled_UDP_Flows
				# Monday | 132208 | 10 | 117366 | 1
				# Tuesday | 109133 | 31 | 103433 | 1
				# Wednesday | 273836 | 22 | 109024 | 0
				# Thursday | 167808 | 95 | 98990 | 0
				# Friday | 347823 | 171 | 102526 | 267
				# NOTE: after checking multiple records, I came to the conclusion that all the labeled flows
				# that are missing are, in fact, non-existent in the CIC-IDS-2017 CSV dataset files, so it is
				# not possible to retrieve their label
				am_datetime = datetime.datetime(year, month, day, am_hour, minute, second, millisecond)
				pm_datetime = datetime.datetime(year, month, day, pm_hour, minute, second, millisecond)
				one_minute = datetime.timedelta(minutes=1)
				five_minutes = datetime.timedelta(minutes=5)
				am_datetime_filter = {
					"biflow_any_first_packet_time": {"$lte": (am_datetime + five_minutes).isoformat(sep=" ")},
					"biflow_any_last_packet_time": {"$gte": (am_datetime - five_minutes).isoformat(sep=" ")}
				}
				pm_datetime_filter = {
					"biflow_any_first_packet_time": {"$lte": (pm_datetime + five_minutes).isoformat(sep=" ")},
					"biflow_any_last_packet_time": {"$gte": (pm_datetime - five_minutes).isoformat(sep=" ")}
				}

				# Select NetGenes MongoDb collection based on current row's protocol
				netgenes_protocol = author_protocol_to_netgenes_protocol[author_protocol]
				netobject_type = "%s_biflows" %(netgenes_protocol)
				biflow_fwd_id = "%s-%s" %(src_ip, netgenes_protocol.upper())
				biflow_bwd_id = "%s-%s" %(dst_ip, netgenes_protocol.upper())
				#print("Collection: '%s'" %(netobject_type))
				curr_collection = curr_db[netobject_type]

				# Search current collection for "Source IP", "Destination IP",
				# "Source Port", "Destination Port"
				# Note: sometimes, the biflow_fwd_id and the biflow_bwd_id are exchanged in different
				# cases, due to the flow being defined in a different way. This is solved by exchanging
				# the source and destination IPs if standard queried results were not found.

				# CICIDS2017 Flow Id is "192.168.10.5-104.16.207.165-54865-443-6" and catches cases where
				# flow_src_ip and flow_src_port are switched up with flow_dst_ip and flow_dst_port
				# NetGenes 5-tuple flow-id is "192.168.10.5-54865-104.16.207.165-443-TCP"
				# e.g., in Friday:
				# > standard (not found on netgenes) - {'bihost_fwd_id': '104.16.207.165-TCP', 'bihost_bwd_id': '192.168.10.5-TCP', 'biflow_src_port': 443, 'biflow_dst_port': 54865}
				# > inverse (found on netgenes) - {'bihost_fwd_id': '192.168.10.5-TCP', 'bihost_bwd_id': '104.16.207.165-TCP', 'biflow_src_port': 54865, 'biflow_dst_port': 443}
				standard_biflow_filter = {
					"bihost_fwd_id": biflow_fwd_id,
					"bihost_bwd_id": biflow_bwd_id,
					"biflow_src_port": src_port,
					"biflow_dst_port": dst_port
				}
				inverse_biflow_filter = {
					"bihost_fwd_id": biflow_bwd_id,
					"bihost_bwd_id": biflow_fwd_id,
					"biflow_src_port": dst_port,
					"biflow_dst_port": src_port
				}

				# df contains the author file of a dataset, which we use to
				# label the corresponding NetGenes dataset file
				update_data = {
					"Threat Class": row["Author Label"],
					"Threat": row["Author Label"],
					"Tool": row["Author Label"]
				}

				am_standard_biflow_filter = {**standard_biflow_filter, **am_datetime_filter}
				pm_standard_biflow_filter = {**standard_biflow_filter, **pm_datetime_filter}
				am_inverse_biflow_filter = {**inverse_biflow_filter, **am_datetime_filter}
				pm_inverse_biflow_filter = {**inverse_biflow_filter, **pm_datetime_filter}

				# Update current collection with 4 new fields
				# filter: {$or: [{Mapping: "Inverse"}, {Mapping: "Standard"}]}
				update_data["Mapping"] = "Standard"
				# uncomment the following code for am-pm standard-inverse stats... "exit()" to stop execution
				"""
				standard_biflow_modifications1 = curr_collection.count_documents(am_standard_biflow_filter)
				standard_biflow_modifications2 = curr_collection.count_documents(pm_standard_biflow_filter)
				standard_biflow_modifications3 = curr_collection.count_documents(am_inverse_biflow_filter)
				standard_biflow_modifications4 = curr_collection.count_documents(pm_inverse_biflow_filter)
				print(am_standard_biflow_filter, "-->", standard_biflow_modifications1)
				print(pm_standard_biflow_filter, "-->", standard_biflow_modifications2)
				print(am_inverse_biflow_filter, "-->", standard_biflow_modifications3)
				print(pm_inverse_biflow_filter, "-->", standard_biflow_modifications4)
				exit()
				"""

				# PRE-SELECT only standard_biflow_filter
				#standardly_filtered_biflow_docs = curr_collection.aggregate(standard_biflow_filter)
				# UPDATE COLLECTIONS HAVING AM/PM TIMES INTO ACCOUNT
				am_standard_biflow_modifications = curr_collection.update_many(am_standard_biflow_filter, {"$set": update_data})
				pm_standard_biflow_modifications = curr_collection.update_many(pm_standard_biflow_filter, {"$set": update_data})
				
				curr_flow_log = "Collection: %s | Standard modifications (AM): %s | Standard modifications (PM): %s | Standard filter: %s" %(
					netobject_type, am_standard_biflow_modifications.modified_count, pm_standard_biflow_modifications.modified_count, standard_biflow_filter)

				if (am_standard_biflow_modifications.modified_count + pm_standard_biflow_modifications.modified_count) == 0:
					update_data["Mapping"] = "Inverse"
					# PRE-SELECT only inverse_biflow_filter
					#inversely_filtered_biflow_docs = curr_collection.aggregate(inverse_biflow_filter)
					# UPDATE COLLECTIONS HAVING AM/PM TIMES INTO ACCOUNT
					am_inverse_biflow_modifications = curr_collection.update_many(am_inverse_biflow_filter, {"$set": update_data})
					pm_inverse_biflow_modifications = curr_collection.update_many(pm_inverse_biflow_filter, {"$set": update_data})

					if (am_inverse_biflow_modifications.modified_count + pm_inverse_biflow_modifications.modified_count) == 0:
						curr_flow_log = "Collection: %s | No modifications | Standard filter: %s | Inverse filter: %s" %(
						netobject_type, standard_biflow_filter, inverse_biflow_filter)
					else:
						curr_flow_log = "Collection: %s | Inverse modifications (AM): %s | Inverse modifications (PM): %s | Inverse filter: %s" %(
						netobject_type, am_inverse_biflow_modifications.modified_count, pm_inverse_biflow_modifications.modified_count, inverse_biflow_filter)
				# else, everything ok
				#print(curr_flow_log)
	mongo_client.close()

def get_compound_label_values(mapping_results, threat_class_results, threat_results, tool_results, separator):
	mapping_compound_value = separator.join(mapping_results)
	threat_class_compound_value = separator.join(threat_class_results)
	threat_compound_value = separator.join(threat_results)
	tool_compound_value = separator.join(tool_results)

	return mapping_compound_value, threat_class_compound_value, threat_compound_value, tool_compound_value

def update_bitalkers_bihosts(dataset_name, database_list):
	print("[+] Now, updating bitalkers and bihosts for '%s'..." %(dataset_name))
	mongo_client = MongoClient("mongodb://localhost:27017")
	biflow_collection_list = ["tcp_biflows", "udp_biflows"]
	bitalker_collection_list = ["tcp_bitalkers", "udp_bitalkers"]
	bihost_collection_list = ["tcp_bihosts", "udp_bihosts"]
	protocol_to_bitalker = {
		"tcp": "tcp_bitalkers",
		"udp": "udp_bitalkers",
	}
	protocol_to_bihost = {
		"tcp": "tcp_bihosts",
		"udp": "udp_bihosts",
	}

	for database_id in database_list:
		curr_db = mongo_client[database_id]
		print("[+] Database: '%s'" %(database_id))
		bitalker_ids = dict()
		bihost_ids = dict()

		curr_db["tcp_biflows"].create_index([("unitalker_id", ASCENDING), ("Mapping", ASCENDING)])
		curr_db["udp_biflows"].create_index([("unitalker_id", ASCENDING), ("Mapping", ASCENDING)])

		# Accessing with bitalker definition
		curr_db["tcp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING), ("bihost_bwd_id", ASCENDING)])
		curr_db["udp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING), ("bihost_bwd_id", ASCENDING)])
		curr_db["tcp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING), ("bihost_bwd_id", ASCENDING), ("Mapping", ASCENDING)])
		curr_db["udp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING), ("bihost_bwd_id", ASCENDING), ("Mapping", ASCENDING)])

		curr_db["tcp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING)])
		curr_db["tcp_bitalkers"].create_index([("bihost_bwd_id", ASCENDING)])
		curr_db["udp_bitalkers"].create_index([("bihost_fwd_id", ASCENDING)])
		curr_db["udp_bitalkers"].create_index([("bihost_bwd_id", ASCENDING)])
		curr_db["tcp_bihosts"].create_index([("bihost_id", ASCENDING)])
		curr_db["udp_bihosts"].create_index([("bihost_id", ASCENDING)])

		for i, bitalker_collection_name in enumerate(bitalker_collection_list):
			bitalker_collection = curr_db[bitalker_collection_name]
			bitalker_results = bitalker_collection.find({}, {"_id": 0, "bitalker_id": 1})
			biflow_collection_name = biflow_collection_list[i]
			curr_protocol = biflow_collection_name.split("_")[0]
			bitalker_ids[curr_protocol] = [bitalker_result["bitalker_id"] for bitalker_result in bitalker_results]

		for i, bihost_collection_name in enumerate(bihost_collection_list):
			bihost_collection = curr_db[bihost_collection_name]
			bihost_results = bihost_collection.find({}, {"_id": 0, "bihost_id": 1})
			biflow_collection_name = biflow_collection_list[i]
			curr_protocol = biflow_collection_name.split("_")[0]
			bihost_ids[curr_protocol] = [bihost_result["bihost_id"] for bihost_result in bihost_results]

		# tcp_biflow, udp_biflow
		for biflow_collection_name in biflow_collection_list:
			curr_protocol = biflow_collection_name.split("_")[0]
			bitalker_collection_name = protocol_to_bitalker[curr_protocol]
			bihost_collection_name = protocol_to_bihost[curr_protocol]

			biflow_collection = curr_db[biflow_collection_name]
			bitalker_collection = curr_db[bitalker_collection_name]
			bihost_collection = curr_db[bihost_collection_name]

			for bitalker_id in bitalker_ids[curr_protocol]:
				fk_bitalker_filter = {"$or": [{"Mapping": "Inverse"}, {"Mapping": "Standard"}], "unitalker_id": bitalker_id}
				bitalker_flow_mapping_results = biflow_collection.distinct("Mapping", fk_bitalker_filter)
				if not bitalker_flow_mapping_results:
					# continue if there are no results in the mapping
					continue
				#bitalker_filter = {"bitalker_id": bitalker_id}
				splitted_unitalker_id = bitalker_id.split("-")
				bihost_fwd = "-".join([splitted_unitalker_id[0], splitted_unitalker_id[2]])
				bihost_bwd = "-".join([splitted_unitalker_id[1], splitted_unitalker_id[2]])
				bitalker_filter = {
					"$or": [
						{"$and": [{"bihost_fwd_id": bihost_fwd}, {"bihost_bwd_id": bihost_bwd}]},
						{"$and": [{"bihost_fwd_id": bihost_bwd}, {"bihost_bwd_id": bihost_fwd}]}
					]
				}
				
				#labels_view = {"_id": 0, "Mapping": 1, "Threat Class": 1, "Threat": 1, "Tool": 1}
				#bitalker_flow_results = biflow_collection.find(fk_bitalker_filter, labels_view).distinct("Threat Class")
				bitalker_flow_threat_class_results = biflow_collection.distinct("Threat Class", fk_bitalker_filter)
				bitalker_flow_threat_results = biflow_collection.distinct("Threat", fk_bitalker_filter)
				bitalker_flow_tool_results = biflow_collection.distinct("Tool", fk_bitalker_filter)
				mapping, threat_class, threat, tool = get_compound_label_values(bitalker_flow_mapping_results, bitalker_flow_threat_class_results, bitalker_flow_threat_results, bitalker_flow_tool_results, "&")

				update_data = {
					"Mapping": mapping,
					"Threat Class": threat_class,
					"Threat": threat,
					"Tool": tool
				}
				bitalker_modifications = bitalker_collection.update_many(bitalker_filter, {"$set": update_data})
				#print("%s:%s" %(bitalker_filter, update_data))
			print("  [+] Finished updating '%s' BiTalkers..." %(curr_protocol))
			for bihost_id in bihost_ids[curr_protocol]:
				fk_bihost_filter = {
					"$or": [{"Mapping": "Inverse"}, {"Mapping": "Standard"}],
					"$or": [{"bihost_fwd_id": bihost_id}, {"bihost_bwd_id": bihost_id}]
				}
				bihost_filter = {"bihost_id": bihost_id}
				bihost_bitalker_mapping_results = bitalker_collection.distinct("Mapping", fk_bihost_filter)
				if not bihost_bitalker_mapping_results:
					# continue if there are no results in the mapping
					continue

				#labels_view = {"_id": 0, "Threat Class": 1, "Threat": 1, "Tool": 1}
				#bihost_flow_results = bitalker_collection.find(fk_bihost_filter, labels_view)
				bihost_bitalker_threat_class_results = bitalker_collection.distinct("Threat Class", fk_bihost_filter)
				bihost_bitalker_threat_results = bitalker_collection.distinct("Threat", fk_bihost_filter)
				bihost_bitalker_tool_results = bitalker_collection.distinct("Tool", fk_bihost_filter)
				mapping, threat_class, threat, tool = get_compound_label_values(bihost_bitalker_mapping_results, bihost_bitalker_threat_class_results, bihost_bitalker_threat_results, bihost_bitalker_tool_results, "+")
				update_data = {
					"Mapping": mapping,
					"Threat Class": threat_class,
					"Threat": threat,
					"Tool": tool
				}
				bihost_modifications = bihost_collection.update_many(bihost_filter, {"$set": update_data})
				#print("%s:%s" %(bihost_filter, update_data))
			print("  [+] Finished updating '%s' BiHosts..." %(curr_protocol))
	return

if __name__ == "__main__":
	"""
	Running this script requires the "s2-author-normalized-labeled-flows" and the
	netgenes unlabeled files imported to the MongoDb.
	
	Label every:
	- Flow
	- Talker
	- Host

	Using three types of labels:
	- Threat Class
	- Threat
	- Tool.
	"""
	# TODO: update biflow netgenes labels for threat class, threat and tool
	
	# ------------
	# CIC-IDS-2017
	# ------------
	cicids2017_author_protocol_to_netgenes_protocol = {
		"6": "tcp",
		"17": "udp"
	}
	# use "s2-author-normalized-labeled-flows" information to label dataset in MongoDb
	map_original_to_netgenes_dataset("CIC-IDS-2017", cicids2017_author_protocol_to_netgenes_protocol)
	# update bitalkers and bihosts labels based on biflow labels (can be done independently of the previous mapping)
	database_list = ["Friday-WorkingHours", "Monday-WorkingHours", "Thursday-WorkingHours",
		"Tuesday-WorkingHours", "Wednesday-WorkingHours"]
	update_bitalkers_bihosts("CIC-IDS-2017", database_list)

	# ------
	# CTU-13
	# ------
	# CTU-13 deactivated
	"""
	ctu13_author_protocol_to_netgenes_protocol = {
		"tcp": "tcp",
		"udp": "udp"
	}
	# use "s2-author-normalized-labeled-flows" information to label dataset in MongoDb
	map_original_to_netgenes_dataset("CTU-13", ctu13_author_protocol_to_netgenes_protocol)
	# TODO: update biflow netgenes labels for threat class, threat and tool
	# update bitalkers and bihosts labels based on biflow labels (can be done independently of the previous mapping)
	database_list = ["botnet-capture-20110810-neris","botnet-capture-20110811-neris",
	"botnet-capture-20110812-rbot", "botnet-capture-20110815-fast-flux", "botnet-capture-20110815-fast-flux-2",
	"botnet-capture-20110815-rbot-dos", "botnet-capture-20110816-donbot", "botnet-capture-20110816-qvod",
	"botnet-capture-20110816-sogou", "botnet-capture-20110817-bot", "botnet-capture-20110818-bot",
	"botnet-capture-20110818-bot-2", "botnet-capture-20110819-bot"]
	update_bitalkers_bihosts("CTU-13", database_list)
	"""