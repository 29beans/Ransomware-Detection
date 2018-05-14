import os
import sys

check_dir=sys.argv[1]+"\\"
check_file_list=os.listdir(check_dir)
#target_string="5CE9577BB246D034960B6E07A448C741ED8337A552AB2D355930E07D099D32415B0AB92E2B8886BA4F7B8ADE5AF08BE29785825554A38BF668F39AFA408CF05FF7B771BEA5C7ECAE8C5F265694C478CD603F73B51BC55368748E30F70A36EZwClose"

for file in check_file_list:
	with open(check_dir+file,'r') as fr:
		data=fr.readlines()
		for line in data:
			if '\t' not in line:
				continue
			if len(line) > 50:
				print(line+" in %s" %file)
			

