import sys
import os

target_dir=sys.argv[1]
target_list=sys.argv[2]
fr=open(target_list, 'r')
file_list=fr.read().split()

for file in file_list:
	os.remove(target_dir+file)
