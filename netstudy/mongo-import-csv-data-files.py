import os
import sys
import subprocess
import time
from pymongo import MongoClient

netobject_types_dir = {
	"ipv4-tcp-biflows.csv": "tcp_biflows",
	"ipv4-tcp-bitalkers.csv": "tcp_bitalkers",
	"ipv4-tcp-bihosts.csv": "tcp_bihosts",
	"ipv4-udp-biflows.csv": "udp_biflows",
	"ipv4-udp-bitalkers.csv": "udp_bitalkers",
	"ipv4-udp-bihosts.csv": "udp_bihosts"
}

mongo_client = MongoClient("mongodb://localhost:27017")
# sys.argv[1] -> netgenes-labeled-csv-data-files
for dname, dirs, files in os.walk(sys.argv[1]):
	for fname in files:
		dataset_id = os.path.basename(os.path.normpath(dname))
		rel_fpath = os.path.join(dname, fname)
		netobject_type = netobject_types_dir[fname]

		# Drop current collection before importing another
		curr_db = mongo_client[dataset_id]
		curr_collection = curr_db[netobject_type]
		curr_collection.drop()

mongo_client.close()
print("[+] All collections (and, consequently, respective databases) dropped..." + 
	" waiting 2 seconds before reconnecting to MongoDb and importing the new databases.")
time.sleep(2)

# sys.argv[1] -> netgenes-labeled-csv-data-files
for dname, dirs, files in os.walk(sys.argv[1]):
	for fname in files:
		dataset_id = os.path.basename(os.path.normpath(dname))
		rel_fpath = os.path.join(dname, fname)
		netobject_type = netobject_types_dir[fname]

		# Import CSV into MongoDb, as is
		cmd = "mongoimport --db=%s --collection=%s --type=csv --headerline --file=%s"\
			%(dataset_id, netobject_type, rel_fpath)

		process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		output, error = process.communicate()
		print(output)