import os
import sys
import csv
import pandas as pd
import numpy as np
from scipy.sparse import *
from pympler.asizeof import asizeof
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import KFold
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score

data_dir=sys.argv[1]+"\\"
k=int(sys.argv[sys.argv.index("-k")+1])

n_list=[]

if "-n" in sys.argv:
	i=sys.argv.index("-n")
	i+=1
	while sys.argv[i].isdigit():
		n_list.append(int(sys.argv[i]))
		i+=1
		if i == len(sys.argv):
			break

def loadCSVwithPandas(n, data_dir=data_dir):
	file_name="norm_"+str(n)+"_gram_vector.csv"
	row_num, col_num = CountRowsAndColumns(file_name)

	X=pd.read_csv(data_dir+file_name, header=None, usecols=list(range(col_num-1)), dtype=np.float16).as_matrix()
	y=pd.read_csv(data_dir+file_name, header=None, usecols=[col_num-1], dtype=np.int8).as_matrix()

	return X, y

def CountRowsAndColumns(file_name, data_dir=data_dir):
	with open(data_dir+file_name,'r', encoding="utf-8") as f:
		data=csv.reader(f)
		row_num=len(f.readlines())
		f.seek(0)
		column_num=len(next(data))
		f.seek(0)
	return row_num, column_num

def SparseMatrix(n, data_dir=data_dir):
	file_name="norm_"+str(n)+"_gram_vector.csv"
	with open(data_dir+file_name,'r',encoding="utf-8") as f:
		data=csv.reader(f)
		row_num, col_num=CountRowsAndColumns(file_name)
		print("row: %d, column: %d" %(row_num, col_num))

		X_sparse_matrix=lil_matrix((row_num,col_num-1),dtype=np.float32)
		y_sparse_matrix=[]

		row_idx=0
		for row in data:
			X_sparse_matrix[row_idx, list(range(col_num-1))]=row[:-1]
			y_sparse_matrix.append(row[-1])
			row_idx+=1
			# print("%d row done" %row_idx)

	return X_sparse_matrix, y_sparse_matrix

# load CSV data into X, y list
def loadCSV(n, n_list=n_list, data_dir=data_dir):

	with open(data_dir+"norm_"+str(n)+"_gram_vector.csv",'r', encoding="utf-8") as f:
		data=csv.reader(f)
		row_num=len(f.readlines())
		f.seek(0)
		col_num=len(next(data))
		f.seek(0)
		print("row: %d, column: %d" %(row_num, col_num))
		X, y = [], []
		row_idx=0
		print("Vector Construction succeed!")

		# load CSV into X, y
		for row in data:
			X.append(row[:-1])
			y.append(row[-1])
			
			index+=1
			X_row=row[:-1]
			X.append(X_row)
			y.append(int(row[-1]))
		
	print("%dth data loading finished" %n)
	# return 0,1
	return X, y
	
#Random Forest classification in k-fold cross validation style
def RFclassification(n_list=n_list, k=k):
	
	for n in n_list:
		
		if n>=4:
			X, y=SparseMatrix(n)
		else:
			X, y=loadCSVwithPandas(n)

		print("load CSV Done!")
		# while True:
			# a=1

		kf=KFold(n_splits=k, shuffle=True)

		# k-fold cross validation start
		turn=0
		for train_index, test_index in kf.split(X):
			turn+=1

			if n>=4:
				X_train, X_test = X[train_index,:], X[test_index,:]
			else:
				X_train, X_test = [X[i] for i in train_index], [X[i] for i in test_index]
			y_train, y_test = [y[i] for i in train_index], [y[i] for i in test_index]
			
			print("model creation start %d" %turn)
			rf=RandomForestClassifier()
			rf.fit(X_train, y_train)
			y_pred=rf.predict(X_test)
			print("model creation finished %d" %turn)
			# for memory management
			# del(X_train, X_test, y_train, y_test)
			accuracy=accuracy_score(y_test, predictions)
			precision=precision_score(y_test, predictions, average=None)
			recall=recall_score(y_test, predictions, average=None)
			
			print("------------ %dth Classification Result (n: %d) -------------" %(turn,n))
			print("Total Accuracy: %.5f" %accuracy)	
			print("benign pre, rec: %.5f, %.5f" %(precision[0],recall[0]))
			print("malware pre, rec: %.5f, %.5f" %(precision[1],recall[1]))
			print("ransom pre, rec: %.5f, %.5f" %(precision[2],recall[2]))
			print()
	
# Classification start
RFclassification()