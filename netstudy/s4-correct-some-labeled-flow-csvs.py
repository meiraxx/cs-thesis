"""
Apply some filters to remove unwanted network objects from the studied datasets
"""

import os
import errno
import pandas as pd

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

def bitalkers_to_unitalkers(bitalker_ids):
	unitalker_ids = []
	# first unitalker_id is equal to the bitalker_id
	for unitalker_id1 in bitalker_ids:
		splitted_bitalker_id = unitalker_id1.split("-")
		# second unitalker_id is equal to the reversed unitalker_id1
		unitalker_id2 = "%s-%s-%s"%(splitted_bitalker_id[1], splitted_bitalker_id[0], splitted_bitalker_id[2])
		unitalker_ids.append(unitalker_id1)
		unitalker_ids.append(unitalker_id2)

	return unitalker_ids

def main():
	tcp_flows_benign_dir = os.path.join("s3-netgenes-labeled-flows", "by-dataset-by-threat")
	tcp_flows_benign_fpath = os.path.join(tcp_flows_benign_dir, "cicids2017-BENIGN.csv")

	tcp_flows_benign_output_dir = "s4-netgenes-labeled-corrected-flows"
	mkdir_p(tcp_flows_benign_output_dir)
	tcp_flows_benign_output_fpath = os.path.join(tcp_flows_benign_output_dir, "cicids2017-BENIGN-corrected.csv")

	df = pd.read_csv(tcp_flows_benign_fpath)

	# TODO: change DF to apply the filter on the flows, which will consequently apply changes on
	# the higher contextual network objects generated from those (talkers and hosts)
	df = df[df["Threat Class"] == "BENIGN"]
	# TODO: save csv in "s4-netgenes-labeled-corrected-flows" directory

	bitalker_ids = ["172.16.0.1-192.168.10.50-TCP", "192.168.10.12-192.168.10.50-TCP",
	"192.168.10.14-192.168.10.50-TCP", "192.168.10.15-192.168.10.50-TCP", "192.168.10.16-192.168.10.50-TCP",
	"192.168.10.17-192.168.10.50-TCP", "192.168.10.19-192.168.10.50-TCP", "192.168.10.25-192.168.10.50-TCP",
	"192.168.10.5-192.168.10.50-TCP", "192.168.10.51-185.170.48.239-TCP", "192.168.10.8-192.168.10.50-TCP",
	"192.168.10.9-192.168.10.50-TCP", "192.168.10.51-192.168.10.50-TCP", "172.16.0.1-192.168.10.51-TCP",
	"192.168.10.8-192.168.10.12-TCP", "192.168.10.8-192.168.10.14-TCP", "192.168.10.8-192.168.10.15-TCP",
	"192.168.10.8-192.168.10.16-TCP", "192.168.10.8-192.168.10.17-TCP", "192.168.10.8-192.168.10.19-TCP",
	"192.168.10.8-192.168.10.25-TCP", "192.168.10.8-192.168.10.5-TCP", "192.168.10.8-192.168.10.51-TCP",
	"192.168.10.8-192.168.10.9-TCP"]

	unitalker_ids = bitalkers_to_unitalkers(bitalker_ids)

	df.drop(
		df.index[
		(df["unitalker_id"].isin(unitalker_ids))
		], inplace = True)

	_df_to_csv(df, tcp_flows_benign_output_fpath, "write")

if __name__ == '__main__':
	main()