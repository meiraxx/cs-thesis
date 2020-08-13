import os
import errno
import pandas
import numpy as np
from random import randint
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

	dataset_logs_dir = os.path.join("s3-flow-mapping-logs", dataset_name)
	mkdir_p(dataset_logs_dir)
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
			print("Database: '%s'" %(database_id))
			flow_logs = ""
			tcp_index_created = False
			udp_index_created = False
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

				if not tcp_index_created and netobject_type == "tcp_biflows":
					# create a compound index
					resp = curr_collection.create_index(
						[
							("bihost_fwd_id", ASCENDING),
							("bihost_bwd_id", ASCENDING),
							("biflow_src_port", ASCENDING),
							("biflow_dst_port", ASCENDING)
						]
					)
					tcp_index_created = True

				if not udp_index_created and netobject_type == "udp_biflows":
					# create a compound index
					resp = curr_collection.create_index(
						[
							("bihost_fwd_id", ASCENDING),
							("bihost_bwd_id", ASCENDING),
							("biflow_src_port", ASCENDING),
							("biflow_dst_port", ASCENDING)
						]
					)
					udp_index_created = True

				# df contains the author file of a dataset, which we use to
				# label the corresponding NetGenes dataset file
				update_data = {
					"Threat Class": row["Author Label"] + str(randint(1, 9)),
					"Threat": row["Author Label"],
					"Tool": row["Author Label"]
				}

				# Update current collection with 4 new fields
				# filter: {$or: [{Mapping: "Inverse"}, {Mapping: "Standard"}]}
				update_data["Mapping"] = "Standard"
				standard_biflow_modifications = curr_collection.update_many(standard_biflow_filter,
					{"$set": update_data})

				curr_flow_log = "Collection: %s | Standard modification: %s | Standard filter: %s" %(
					netobject_type, standard_biflow_modifications.modified_count,standard_biflow_filter)

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
				
				flow_logs += curr_flow_log + "\n"
				#print(curr_flow_log)
				# else, everything ok

				"""
				standardly_queried_biflows = curr_collection.find(standard_biflow_filter, biflow_view)
				for standardly_queried_biflow in standardly_queried_biflows:
					print(standardly_queried_biflow)
				inversely_queried_biflows = curr_collection.find(inverse_biflow_filter, biflow_view)
				for inversely_queried_biflow in inversely_queried_biflows:
					print(inversely_queried_biflow)
				#mongo_client.close()
				#exit()
				"""
				
			dataset_logs_fpath = os.path.join(dataset_logs_dir, "%s.txt" %(database_id))
			with open(dataset_logs_fpath, "w") as f:
				f.write(flow_logs)

	mongo_client.close()
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
	#map_original_to_netgenes_dataset("CIC-IDS-2017", cicids2017_author_protocol_to_netgenes_protocol)
	# TODO: update biflow netgenes labels for threat class, threat and tool
	# TODO: update bitalkers and bihosts labels based on biflow labels (can be done independently of the previous mapping)

	# ------
	# CTU-13
	# ------
	ctu13_author_protocol_to_netgenes_protocol = {
		"tcp": "tcp",
		"udp": "udp"
	}
	# use "s2-author-normalized-labeled-flows" information to label dataset in MongoDb
	#map_original_to_netgenes_dataset("CTU-13", ctu13_author_protocol_to_netgenes_protocol)
	# TODO: update biflow netgenes labels for threat class, threat and tool
	# TODO: update bitalkers and bihosts labels based on biflow labels (can be done independently of the previous mapping)