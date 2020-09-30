def get_counts(lst):
	unique_lst = list(set(lst))
	count_dict = dict()
	for x in unique_lst:
		count_dict[x] = lst.count(x)
	return count_dict

def get_max_count_value(count_dict, excluded_keys=None):
	max_count = 0
	max_key = ""
	for key in count_dict:
		if key in excluded_keys: continue
		count = count_dict[key]
		if count > max_count:
			max_count = count
			max_key = key

	return max_key

def get_label_value_old(dataset_name, label_values):
	label_counts = get_counts(label_values)

	if dataset_name == "CIC-IDS-2017":
		label_compound_value = max(label_values, key=label_values.count)
		if label_compound_value == "BENIGN" and len(label_counts) > 1:
			label_compound_value = get_max_count_value(label_counts, "BENIGN")

	return label_compound_value

"""
#flow_logs = ""
#dataset_logs_dir = os.path.join("s3-flow-mapping-logs", dataset_name)
#mkdir_p(dataset_logs_dir)
#flow_logs += curr_flow_log + "\n"
#dataset_logs_fpath = os.path.join(dataset_logs_dir, "%s.txt" %(database_id))
#with open(dataset_logs_fpath, "w") as f:
#	f.write(flow_logs)
"""