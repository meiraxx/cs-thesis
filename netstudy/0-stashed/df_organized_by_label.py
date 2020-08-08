# get all labels
labels = [x[0] for x in df[["Author Label"]].drop_duplicates().values]

for label in labels:
	labeled_df = df[df["Author Label"] == label]
	output_fpath = os.path.join(output_dir, "%s.csv"%(label))

	try:
		if os.path.isfile(output_fpath):
			labeled_df.to_csv(output_fpath, index=False, mode='a', header=False)
		else:
			labeled_df.to_csv(output_fpath, index=False)
	except UnicodeDecodeError:
		print("[!] Error parsing file '%s' due to 'utf-8' undecodable character" %(fpath))
		continue