import os
import sys
import subprocess

netobject_types_dir = {
	"ipv4-tcp-biflows.csv": "tcp_biflows",
	"ipv4-tcp-bitalkers.csv": "tcp_bitalkers",
	"ipv4-tcp-bihosts.csv": "tcp_bihosts",
	"ipv4-udp-biflows.csv": "udp_biflows",
	"ipv4-udp-bitalkers.csv": "udp_bitalkers",
	"ipv4-udp-bihosts.csv": "udp_bihosts"
}

for dname, dirs, files in os.walk(sys.argv[1]):
	for fname in files:
		rel_fpath = os.path.join(dname, fname)
		dataset_id = os.path.basename(os.path.normpath(dname))
		netobject_type = netobject_types_dir[fname]

		cmd = "mongoimport --db=%s --collection=%s --type=csv --headerline --file=%s"\
			%(dataset_id, netobject_type, rel_fpath)

		process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		output, error = process.communicate()
		print(output)