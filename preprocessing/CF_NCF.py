import os
import sys
import csv
import pandas as pd
import numpy as np
from scipy.sparse import *

data_dir=sys.argv[1]+"\\"
output_dir="C:\\exp_data\\RTFRD\\CF-NCF_anal\\"

n_list=[]

if "-n" in sys.argv:
	i=sys.argv.index("-n")
	i+=1
	while sys.argv[i].isdigit():
		n_list.append(int(sys.argv[i]))
		i+=1
		if i == len(sys.argv):
			break

def CountRowsAndColumns(file_name, data_dir=data_dir):
	with open(data_dir+file_name,'r', encoding="utf-8") as f:
		data=csv.reader(f)
		row_num=len(f.readlines())
		f.seek(0)
		col_num=len(next(data))
		f.seek(0)
	return row_num, col_num

def CountZeroValues(ben_f_col, mal_f_col, ran_f_col):
	ben_zero_count=ben_f_col.count(0)
	mal_zero_count=mal_f_col.count(0)
	ran_zero_count=ran_f_col.count(0)

	return ben_zero_count, mal_zero_count, ran_zero_count

def CF(zero_cnt, total_num):
	return (1-(zero_cnt/total_num))

def NCF(zero_cnt1, zero_cnt2, total_num1, total_num2):
	return (1- (zero_cnt1+zero_cnt2)/(total_num1+total_num2))

def SparseMatrix(file_name, row_num, col_num, data_dir=data_dir):
	# file_name="norm_"+str(n)+"_gram_vector.csv"
	# file_name=str(n)+"_gram_vector.csv"

	with open(data_dir+file_name,'r',encoding="utf-8") as f:
		data=csv.reader(f)
		# print("row: %d, column: %d" %(row_num, col_num))

		sparse_matrix=lil_matrix((row_num,col_num), dtype=np.float32)

		row_idx=0
		for row in data:
			sparse_matrix[row_idx, :]=row
			row_idx+=1
			# print("%d row done" %row_idx)
	# print(sparse_matrix)
	return sparse_matrix

def CF_NCF(file_name, n):
	row_num, col_num = CountRowsAndColumns(file_name)
	print("row: %d, col: %d" %(row_num, col_num))
	ben_CF, mal_CF, ran_CF = [], [], []
	ben_NCF, mal_NCF, ran_NCF = [], [], []

	# with open(data_dir+file_name, 'r') as f:
		# data=csv.reader(f)
	sparse_matrix=SparseMatrix(file_name, row_num, col_num)
	# Extract one-feature column list while col_num-1 iterations
	for i in range(col_num-1):
		# col_idx=0
		# f_col=[]
		# f.seek(0)
		# for row in data:
			# f_col.append([float(row[col_idx]), row[col_num-1]])
			# col_idx+=1
		# print(len(f_col))
		# f_col=pd.read_csv(data_dir+file_name, header=None, usecols=[i,col_num-1]).as_matrix()
		f_col=sparse_matrix[:,[i,col_num-1]].toarray()
		# print(f_col)
		# , sparse_matrix.getcol(col_num-1)
		# print(f_col)

		# Construct one-feature column for each class label
		ben_f_col, mal_f_col, ran_f_col=[], [], []
		for j in range(row_num):
			class_label=f_col[j][1]
			if class_label == 0:
				ben_f_col.append(f_col[j][0])
			elif class_label == 1:
				mal_f_col.append(f_col[j][0])
			elif class_label == 2:
				ran_f_col.append(f_col[j][0])
			else:
				print("Class Label error! in row%d" %j)
		# print("col%d done..." %(i+1))

		# Count Class Frequency
		ben_num=len(ben_f_col)
		mal_num=len(mal_f_col)
		ran_num=len(ran_f_col)

		ben_zero_cnt, mal_zero_cnt, ran_zero_cnt = CountZeroValues(ben_f_col, mal_f_col, ran_f_col)

		# Record CF - NCF for each class
		ben_cf=CF(ben_zero_cnt, ben_num)
		ben_ncf=NCF(mal_zero_cnt, ran_zero_cnt, mal_num, ran_num)
		ben_CF.append(ben_cf)
		ben_NCF.append(ben_ncf)

		mal_cf=CF(mal_zero_cnt, mal_num)
		mal_ncf=NCF(ben_zero_cnt, ran_zero_cnt, ben_num, ran_num)
		mal_CF.append(mal_cf)
		mal_NCF.append(mal_ncf)		

		ran_cf=CF(ran_zero_cnt, ran_num)
		ran_ncf=NCF(ben_zero_cnt, mal_zero_cnt, ben_num, mal_num)
		ran_CF.append(ran_cf)
		ran_NCF.append(ran_ncf)

	# Save CF-NCF results into CSV file
	fw1=open(output_dir+"ben_"+str(n)+"_gram_CF_NCF.csv",'w',newline='')
	writer1=csv.writer(fw1)

	fw2=open(output_dir+"mal_"+str(n)+"_gram_CF_NCF.csv",'w',newline='')
	writer2=csv.writer(fw2)

	fw3=open(output_dir+"ran_"+str(n)+"_gram_CF_NCF.csv",'w',newline='')
	writer3=csv.writer(fw3)

	writer1.writerow(ben_CF)
	writer1.writerow(ben_NCF)

	writer2.writerow(mal_CF)
	writer2.writerow(mal_NCF)

	writer3.writerow(ran_CF)
	writer3.writerow(ran_NCF)

	fw1.close()
	fw2.close()
	fw3.close()


for n in n_list:
	file_name="norm_"+str(n)+"_gram_vector.csv"
	CF_NCF(file_name, n)
	print("CF-NCF Analysis Done...! (n: %d)" %n)