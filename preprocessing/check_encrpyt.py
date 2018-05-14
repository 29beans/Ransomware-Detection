import sys
import os

target_dir=sys.argv[1]
file_list=os.listdir(target_dir)

for file in file_list:
	f=open(target_dir+file, 'r')
	#print("file: %s" %file)
	dump=f.read()
	if "0000" in dump:
		print(file)
	f.close()
