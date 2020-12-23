def calc_biflow_confusionMatrix_by_bitalker(biflow_positive_results, biflow_negative_results, class_bitalker_ids):
	class_unitalker_ids = list()
	for bitalker_id in class_bitalker_ids:
		unitalker_ids = bitalker_id_to_unitalker_ids(bitalker_id)
		class_unitalker_ids.append(unitalker_ids[0])
		class_unitalker_ids.append(unitalker_ids[1])

	biflow_tp = 0
	biflow_fp = 0
	for biflow in biflow_positive_results:
		if biflow["unitalker_id"] in class_unitalker_ids:
			biflow_tp += 1
		else:
			biflow_fp += 1

	biflow_tn = 0
	biflow_fn = 0
	for biflow in biflow_negative_results:
		if biflow["unitalker_id"] in class_unitalker_ids:
			biflow_fn += 1
		else:
			biflow_tn += 1

	return biflow_tp, biflow_tn, biflow_fp, biflow_fn

def test_biflows_by_bitalker(flows_df, attack_type, class_bitalker_ids, bitalker_positive_results):
	# Bi-Flow Filter
	unitalker_ids_list = [bitalker_id_to_unitalker_ids(bitalker["bitalker_id"]) for bitalker in bitalker_positive_results]
	biflows_ordered_dict_list = flows_df.to_dict("records", into=OrderedDict)
	biflow_positive_results, biflow_negative_results = filter_biflows_ordered_dict(biflows_ordered_dict_list, attack_type, unitalker_ids_list)
	total_biflows = len(biflows_ordered_dict_list)
	print("Flows:", total_biflows)
	print("Filtered Flows:", len(biflow_positive_results))
	print("The following results are based on bi-talker filters only, not on author labels, so they are highly unreliable.")
	biflow_tp, biflow_tn, biflow_fp, biflow_fn = calc_biflow_confusionMatrix_by_bitalker(biflow_positive_results, biflow_negative_results, class_bitalker_ids)
	calc_metrics(biflow_tp, biflow_tn, biflow_fp, biflow_fn, total_biflows)

	return

if dataset_id=="cicids2017-Thursday-WorkingHours":
	# ---------
	# Port Scan
	# ---------
	# Note: this needed to have been properly labeled by the dataset authors, cannot accurately and fairly label it manually
	attack_type = "Port Scan"
	label_text = "PortScan"
	thursday_portscan_bitalker_ids = ["192.168.10.8-192.168.10.12-TCP", "192.168.10.8-192.168.10.14-TCP", "192.168.10.8-192.168.10.15-TCP", "192.168.10.8-192.168.10.16-TCP", "192.168.10.8-192.168.10.17-TCP", "192.168.10.8-192.168.10.19-TCP", "192.168.10.8-192.168.10.25-TCP", "192.168.10.8-192.168.10.5-TCP", "192.168.10.8-192.168.10.50-TCP", "192.168.10.8-192.168.10.51-TCP", "192.168.10.8-192.168.10.9-TCP", "172.16.0.1-192.168.10.51-TCP"]
	bitalker_positive_results, bitalker_negative_results = test_bitalkers(talkers_df, attack_type, label_text, thursday_portscan_bitalker_ids)
	test_biflows_by_bitalker(flows_df, attack_type, thursday_portscan_bitalker_ids, bitalker_positive_results)