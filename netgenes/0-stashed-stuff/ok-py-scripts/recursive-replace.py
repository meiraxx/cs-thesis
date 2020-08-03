import os

for dname, dirs, files in os.walk("csv"):
	for fname in files:
		fpath = os.path.join(dname, fname)
		
		with open(fpath, "r") as f:
			s = f.read()

		s = s.replace(",", ",")
		#s = s.replace("False", "0")
		#s = s.replace("True", "1")

		with open(fpath, "w") as f:
			f.write(s)