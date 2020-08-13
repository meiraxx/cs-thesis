import os
import sys

def replace_string_in_file(file_path, original_string, new_string):
	with open(file_path, "r") as f:
		s = f.read()

	s = s.replace(original_string, new_string)

	with open(file_path, "w") as f:
		f.write(s)

for dname, dirs, files in os.walk(sys.argv[1]):
	print("Working on '%s' directory..."%(dname))
	for fname in files:
		try:
			fpath = os.path.join(dname, fname)
			#replace_string_in_file(fpath, "}C", "}\nC")
			#replace_string_in_file(fpath, "biflow_any_packet_iat", "biflow_any_packet_iat")
			#replace_string_in_file(fpath, "biflow_fwd_packet_iat", "biflow_fwd_packet_iat")
			#replace_string_in_file(fpath, "biflow_bwd_packet_iat", "biflow_bwd_packet_iat")
			#replace_string_in_file(fpath, "|", ",")
			#replace_string_in_file(fpath, "False", "0")
			#replace_string_in_file(fpath, "True", "1")
		except (UnicodeDecodeError, PermissionError):
			continue

