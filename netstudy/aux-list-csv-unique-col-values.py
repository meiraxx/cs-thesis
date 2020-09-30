import os
import pandas

def unique_cols(step_dir, dataset_name, column_name):
	input_dir = os.path.join(step_dir, dataset_name)
	unique_lst = []
	for dname, dirs, files in os.walk(input_dir):
		for fname in files:
			fpath = os.path.join(dname, fname)
			df = pandas.read_csv(fpath).drop_duplicates()
			curr_unique_lst = df[column_name].unique()
			for elem in curr_unique_lst:
				unique_lst.append(elem)

	return list(set(unique_lst))

#cicids2017_unique_cols = unique_cols("s2-author-normalized-labeled-flows", "CIC-IDS-2017", "L3-L4 Protocol")
#cicids2017_unique_cols = unique_cols("s0-author-labeled-flows", "CIC-IDS-2017", " Label")
cicids2017_unique_cols = unique_cols("s2-author-normalized-labeled-flows", "CIC-IDS-2017", "Author Label")
print("CIC-IDS-2017: %s"% (cicids2017_unique_cols))

#ctu13_unique_cols = unique_cols("s2-author-normalized-labeled-flows", "CTU-13", "L3-L4 Protocol")
#ctu13_unique_cols = unique_cols("s0-author-labeled-flows", "CTU-13", "Label")
ctu13_unique_cols = unique_cols("s2-author-normalized-labeled-flows", "CTU-13", "Author Label")
print("CTU-13: %s"% (ctu13_unique_cols))