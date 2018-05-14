import os
import sys
import csv

target_dir=sys.argv[1]+"\\"
output_dir=target_dir+"normalized\\"
target_file_list=os.listdir(target_dir)

for file in target_file_list:
	if os.path.isdir(target_dir+file):
		target_file_list.pop(target_file_list.index(file))

for file in target_file_list:
	with open(target_dir+file,'r') as f:
		data=csv.reader(f)
		row_num=len(f.readlines())
		f.seek(0)
		column_num=len(next(data))
		f.seek(0)

		fw=open(output_dir+"norm_"+file,'w',newline='')
		writer=csv.writer(fw)

		for row in data:
			X, y = list(map(int, row[:-1])), row[-1]
			X_sum=sum(X)
			norm_vec=[value/X_sum for value in X]
			norm_vec.append(y)
			writer.writerow(norm_vec)

		fw.close()
	print("%s ..... done" %file)