import os

def replace_string_in_file(file_path, original_string, new_string):
	with open(file_path, "r") as f:
		s = f.read()

	s = s.replace(original_string, new_string)

	with open(file_path, "w") as f:
		f.write(s)

for dname, dirs, files in os.walk("csv"):
	for fname in files:
		replace_string_in_file(fpath, "|", ",")
		#replace_string_in_file(fpath, "False", "0")
		#replace_string_in_file(fpath, "True", "1")