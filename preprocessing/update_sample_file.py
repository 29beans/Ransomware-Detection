import sys
import os

source_dir=sys.argv[1]+"\\" # directory containing training/testing list files which should be updated
source_file_list=os.listdir(source_dir)
update_plan_dir=sys.argv[2]+"\\" # original sample directory where a few files were deleted
update_plan_file_list=os.listdir(update_plan_dir)

for file in source_file_list:
	f=open(source_dir+file, 'r')
	sample_list=f.read().split()
	f.close()
	fw=open(source_dir+file, 'w')

	for sample in sample_list:
		if sample in update_plan_file_list:
			fw.write(sample+"\n")
	fw.close()
