# USE MongoDb aggregations and schemas, it's really useful.
"""
1. Get threat-class flows, talkers and hosts, into separate CSVs
2. Use AI to study those
"""
import os
import errno
import pandas as pd
from pymongo import MongoClient, ASCENDING, DESCENDING
import time

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

def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise

def clear_dir(target_dir, target_ext):
	filelist = [ f for f in os.listdir(target_dir) if f.endswith(target_ext) ]
	for f in filelist:
	    os.remove(os.path.join(target_dir, f))

def _df_to_csv(df, output_fpath, operation):
	if operation == "write":
		df.to_csv(output_fpath, index=False)
	elif operation == "append":
		if os.path.isfile(output_fpath):
			df.to_csv(output_fpath, index=False, mode='a', header=False)
		else:
			df.to_csv(output_fpath, index=False)


def mongo_to_csv(database_list, dataset_name, output_grouping, output_dir="."):
	clear_dir(output_dir, ".csv")
	
	mongo_client = MongoClient("mongodb://localhost:27017")
	# df.to_csv('my_csv.csv', mode='a', header=False)
	for file_name in database_list:
		curr_db = mongo_client[file_name]
		collection = curr_db["tcp_biflows"]

		collection.create_index([("Threat Class", ASCENDING)])
		# UniTalker sort query
		sort_query = [("unitalker_id", ASCENDING), ("biflow_any_first_packet_time", ASCENDING)]
		# UniHost sort query
		#sort_query = [("bihost_fwd_id", ASCENDING), ("biflow_any_first_packet_time", ASCENDING)]
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
			df = read_mongo(file_name, 'tcp_biflows', threat_class_filter, sort_query, 'localhost', 27017)
			print("[T] Read took", round(time.time() - mongo_read_time, 3), "seconds to complete")
			# work with DF

			# ------
			# OUTPUT
			# ------
			if output_grouping == "by-dataset-by-file-by-threat":
				output_fpath = os.path.join(output_dir, '%s-%s-%s.csv'%(dataset_name, file_name, threat_class))
				_df_to_csv(df, output_fpath, "write")
			elif output_grouping == "by-dataset-by-threat":
				output_fpath = os.path.join(output_dir, '%s-%s.csv'%(dataset_name, threat_class))
				_df_to_csv(df, output_fpath, "append")
				
			#df.to_csv(output_fpath, index=False)
			
	mongo_client.close()
	

if __name__ == '__main__':
	output_dir = "s3-labeled-csvs"
	mkdir_p(output_dir)
	cicids2017_database_list = ["Friday-WorkingHours", "Monday-WorkingHours", "Thursday-WorkingHours",
		"Tuesday-WorkingHours", "Wednesday-WorkingHours"]
	ctu13_database_list = ["botnet-capture-20110810-neris","botnet-capture-20110811-neris",
		"botnet-capture-20110812-rbot", "botnet-capture-20110815-fast-flux", "botnet-capture-20110815-fast-flux-2",
		"botnet-capture-20110815-rbot-dos", "botnet-capture-20110816-donbot", "botnet-capture-20110816-qvod",
		"botnet-capture-20110816-sogou", "botnet-capture-20110817-bot", "botnet-capture-20110818-bot",
		"botnet-capture-20110818-bot-2", "botnet-capture-20110819-bot"]

	mongo_to_csv(cicids2017_database_list, "cicids2017", "by-dataset-by-file-by-threat", output_dir)
	


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