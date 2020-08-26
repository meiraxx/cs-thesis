import os
import errno
import pandas
import numpy as np
#from random import randint
from pymongo import MongoClient, ASCENDING, DESCENDING

def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise

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
	normalized_header_str = "L3-L4 Protocol,Source IP,Source Port,Destination IP,Destination Port,Author Label"
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

			biflow_compound_index = [
				("bihost_fwd_id", ASCENDING),
				("bihost_bwd_id", ASCENDING),
				("biflow_src_port", ASCENDING),
				("biflow_dst_port", ASCENDING)
			]
			curr_db["tcp_biflows"].create_index(biflow_compound_index)
			curr_db["udp_biflows"].create_index(biflow_compound_index)

			for index, row in df.iterrows():
				# Get parameters from DF
				author_protocol = str(row["L3-L4 Protocol"])
				src_ip = str(row["Source IP"])
				dst_ip = str(row["Destination IP"])
				src_port = int(row["Source Port"])
				dst_port = int(row["Destination Port"])

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
				# e.g.:
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

				# Update current collection with 4 new fields
				# filter: {$or: [{Mapping: "Inverse"}, {Mapping: "Standard"}]}
				update_data["Mapping"] = "Standard"
				standard_biflow_modifications = curr_collection.update_many(standard_biflow_filter,
					{"$set": update_data})

				curr_flow_log = "Collection: %s | Standard modification: %s | Standard filter: %s" %(
					netobject_type, standard_biflow_modifications.modified_count, standard_biflow_filter)

				if standard_biflow_modifications.modified_count == 0:
					update_data["Mapping"] = "Inverse"
					inverse_biflow_modifications = curr_collection.update_many(inverse_biflow_filter,
						{"$set": update_data})
					if inverse_biflow_modifications.modified_count == 0:
						curr_flow_log = "Collection: %s | No modification | Standard filter: %s | Inverse filter: %s" %(
						netobject_type, standard_biflow_filter, inverse_biflow_filter)
					else:
						curr_flow_log = "Collection: %s | Inverse modification: %s | Inverse filter: %s" %(
						netobject_type, inverse_biflow_modifications.modified_count, inverse_biflow_filter)
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
		# Accessing bitalker records with unitalker key (wrong)
		#curr_db["tcp_bitalkers"].create_index([("unitalker_id", ASCENDING)])
		#curr_db["udp_bitalkers"].create_index([("unitalker_id", ASCENDING)])
		#curr_db["tcp_bitalkers"].create_index([("unitalker_id", ASCENDING), ("Mapping", ASCENDING)])
		#curr_db["udp_bitalkers"].create_index([("unitalker_id", ASCENDING), ("Mapping", ASCENDING)])
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

	# ------------
	# CIC-IDS-2017
	# ------------
	cicids2017_author_protocol_to_netgenes_protocol = {
		"6": "tcp",
		"17": "udp"
	}
	# use "s2-author-normalized-labeled-flows" information to label dataset in MongoDb
	map_original_to_netgenes_dataset("CIC-IDS-2017", cicids2017_author_protocol_to_netgenes_protocol)
	# TODO: update biflow netgenes labels for threat class, threat and tool
	# update bitalkers and bihosts labels based on biflow labels (can be done independently of the previous mapping)
	database_list = ["Friday-WorkingHours", "Monday-WorkingHours", "Thursday-WorkingHours",
		"Tuesday-WorkingHours", "Wednesday-WorkingHours"]
	update_bitalkers_bihosts("CIC-IDS-2017", database_list)

	# ------
	# CTU-13
	# ------
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