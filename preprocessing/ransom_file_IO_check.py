import sys
import os

ransom_dir=sys.argv[1]
target_ransom_list=sys.argv[2]

fr=open(target_ransom_list, 'r')
file_list=fr.read().split()
ransom_filtered=os.listdir(ransom_dir)

print("-"*10+"file list existing in ransom directory(filtered)"+"-"*10)

for file in file_list:
	if file+".exe.txt" in ransom_filtered:
		print("%s" %file)
