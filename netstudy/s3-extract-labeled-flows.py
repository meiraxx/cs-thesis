# USE MongoDb aggregations and schemas, it's really useful.
"""
Get threat-class flows, talkers and hosts, into separate CSVs
"""
import os
import errno
import pandas as pd
from pymongo import MongoClient, ASCENDING, DESCENDING
import time
from utils import *
# for some reason, the asterisk is not catching this function (wtf)
from utils import _df_to_csv

def _connect_mongo(host, port, username, password, db):
	""" A util for making a connection to mongo """

	if username and password:
		mongo_uri = 'mongodb://%s:%s@%s:%s/%s' % (username, password, host, port, db)
		conn = MongoClient(mongo_uri)
	else:
		conn = MongoClient(host, port)
	return conn[db]

def read_mongo(db, collection, filter_query={}, sort_query={}, host='localhost', port=27017, username=None, password=None, no_id=True):
	""" Read from Mongo and Store into DataFrame """

	# Connect to MongoDB
	db = _connect_mongo(host=host, port=port, username=username, password=password, db=db)

	# Make a query to the specific DB and Collection
	cursor = db[collection].find(filter_query).sort(sort_query)

	# Expand the cursor and construct the DataFrame
	df = pd.DataFrame(list(cursor))

	# Delete the _id
	if no_id and '_id' in df:
		del df['_id']

	return df

def mongo_to_csv(database_list, dataset_name, l4_protocol, output_grouping, output_dir="."):
	mongo_client = MongoClient("mongodb://localhost:27017")
	for file_name in database_list:
		curr_db = mongo_client[file_name]
		collection = curr_db["%s_biflows"%(l4_protocol)]

		collection.create_index([("Threat Class", ASCENDING)])
		# UniTalker sort query
		sort_query = [("unitalker_id", ASCENDING), ("biflow_any_first_packet_time", ASCENDING)]
		# UniHost sort query
		#sort_query = [("bihost_fwd_id", ASCENDING), ("biflow_any_first_packet_time", ASCENDING)]
		# Just TIME sort query
		#sort_query = [("biflow_any_first_packet_time", ASCENDING)]
		
		collection.create_index(sort_query)
		threat_class_results = collection.distinct("Threat Class", {})

		for threat_class in threat_class_results:
			# Threat Class filter query
			if threat_class:
				# filter for specific threat class
				threat_class_filter = {"Threat Class": threat_class}
			else:
				# None -> filter for no threat class
				threat_class_filter = {"Threat Class" : {"$exists": False, "$eq": None}}
			mongo_read_time = time.time()
			df = read_mongo(file_name, '%s_biflows'%(l4_protocol), threat_class_filter, sort_query, 'localhost', 27017)
			print("[T] Read took", round(time.time() - mongo_read_time, 3), "seconds to complete")
			# work with DF

			if not threat_class:
				# if the threat class (and, implicitly, the other stats) does not exist,
				# we will still put it (them) in the CSV

				# note: maintain mongodb order by orderly defining each value
				df["Mapping"] = "None"
				df["Threat"] = "None"
				df["Threat Class"] = "None"
				df["Tool"] = "None"

			# ------
			# OUTPUT
			# ------
			if output_grouping == "by-dataset-by-file-by-threat":
				output_fpath = os.path.join(output_dir, '%s-%s-%s-ipv4-%s-biflows.csv'%(dataset_name, file_name, threat_class, l4_protocol))
				_df_to_csv(df, output_fpath, "write")
			elif output_grouping == "by-dataset-by-file":
				output_fpath = os.path.join(output_dir, '%s-%s-ipv4-%s-biflows.csv'%(dataset_name, file_name, l4_protocol))
				_df_to_csv(df, output_fpath, "append")
			elif output_grouping == "by-dataset-by-threat":
				output_fpath = os.path.join(output_dir, '%s-%s-ipv4-%s-biflows.csv'%(dataset_name, threat_class, l4_protocol))
				_df_to_csv(df, output_fpath, "append")
			elif output_grouping == "by-dataset":
				output_fpath = os.path.join(output_dir, '%s-ipv4-%s-biflows.csv'%(dataset_name, l4_protocol))
				_df_to_csv(df, output_fpath, "append")
			#df.to_csv(output_fpath, index=False)
			
	mongo_client.close()
	

if __name__ == '__main__':
	# USAGE: python s3-extract-labeled-flows.py
	#output_dir1 = os.path.join("s3-netgenes-labeled-flows", "by-dataset-by-file-by-threat")
	output_dir2 = os.path.join("s3-netgenes-labeled-flows", "by-dataset-by-file")
	output_dir3 = os.path.join("s3-netgenes-labeled-flows", "by-dataset-by-threat")
	output_dir4 = os.path.join("s3-netgenes-labeled-flows", "by-dataset")
	#mkdir_p(output_dir1)
	#clear_dir(output_dir1, ".csv")
	mkdir_p(output_dir2)
	clear_dir(output_dir2, ".csv")
	mkdir_p(output_dir3)
	clear_dir(output_dir3, ".csv")
	mkdir_p(output_dir4)
	clear_dir(output_dir4, ".csv")

	cicids2017_database_list = ["Friday-WorkingHours", "Monday-WorkingHours", "Thursday-WorkingHours",
		"Tuesday-WorkingHours", "Wednesday-WorkingHours"]

	# Extract TCP flows
	#mongo_to_csv(cicids2017_database_list, "cicids2017", "tcp", "by-dataset-by-file-by-threat", output_dir1)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "tcp", "by-dataset-by-file", output_dir2)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "tcp", "by-dataset-by-threat", output_dir3)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "tcp", "by-dataset", output_dir4)
	
	# Extract UDP flows
	#mongo_to_csv(cicids2017_database_list, "cicids2017", "udp", "by-dataset-by-file-by-threat", output_dir1)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "udp", "by-dataset-by-file", output_dir2)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "udp", "by-dataset-by-threat", output_dir3)
	mongo_to_csv(cicids2017_database_list, "cicids2017", "udp", "by-dataset", output_dir4)

	"""
	ctu13_database_list = ["botnet-capture-20110810-neris","botnet-capture-20110811-neris",
		"botnet-capture-20110812-rbot", "botnet-capture-20110815-fast-flux", "botnet-capture-20110815-fast-flux-2",
		"botnet-capture-20110815-rbot-dos", "botnet-capture-20110816-donbot", "botnet-capture-20110816-qvod",
		"botnet-capture-20110816-sogou", "botnet-capture-20110817-bot", "botnet-capture-20110818-bot",
		"botnet-capture-20110818-bot-2", "botnet-capture-20110819-bot"]
	"""
	
	


"""
#mongo_client = MongoClient("mongodb://localhost:27017")
no_id_view = {
	"_id": 0
}


curr_db = mongo_client["Friday-WorkingHours"]
biflow_collection = curr_db["tcp_biflows"]
biflow_collection.create_index([("Threat Class", ASCENDING)])

threat_class_filter = {"Threat Class": "PortScan"}

mydoc = biflow_collection.find(threat_class_filter)


#mongo_client.close()
"""