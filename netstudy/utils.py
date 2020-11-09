import os
import errno
import pandas as pd
import shutil

def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise

def replace_string_in_file(file_path, original_string, new_string):
	with open(file_path, "r") as f:
		s = f.read()

	s = s.replace(original_string, new_string)

	with open(file_path, "w") as f:
		f.write(s)

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

def rmdir(dir_path):
	shutil.rmtree(dir_path)