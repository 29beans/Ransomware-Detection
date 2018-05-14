import sys
import os

target_file_path_1=sys.argv[1]
#target_file_path_2=sys.argv[2]
train_file_path_1=sys.argv[2]
train_file_path_2=sys.argv[3]

f1=open(target_file_path_1, 'r')
#f2=open(target_file_path_2, 'r')

t1=open(train_file_path_1,'r')
t2=open(train_file_path_2,'r')

f1.readline()
#f2.readline()

def Delete_DLL(target_list):
	result_list=[]
	for line in target_list:
		if '\t' not in line:
			continue
		api=line.split()[0]
		result_list.append(api)
	return result_list

def Zw_To_Nt_Translator(target_list):
	for i in range(len(target_list)):
		Zw_starter=target_list[i]
		if Zw_starter.startswith('Zw'):
			target_list[i]=Zw_starter.replace(Zw_starter[0:2],'Nt')

data_1=f1.readlines()
#data_2=f2.readlines()

data_1=Delete_DLL(data_1)
#data_2=Delete_DLL(data_2)

Zw_To_Nt_Translator(data_1)

train_1=t1.readlines()
train_2=t2.readlines()

dic1={}
dic2={}

for line in train_1:
	if '\t' not in line:
		break
	key_value=line.split('\t')
	dic1[key_value[0]]=float(key_value[1])


for line in train_2:
	if '\t' not in line:
		break
	key_value=line.split('\t')
	dic2[key_value[0]]=float(key_value[1])

score_1=0
score_2=0
print(len(data_1))

for i in range(len(data_1)-1):
	n_gram=str(tuple(data_1[i:i+2]))
	
	if n_gram in dic1:
		score_1+=dic1[n_gram]


for i in range(len(data_1)-1):
	n_gram=str(tuple(data_1[i:i+2]))
	
	if n_gram in dic2:
		score_2+=dic2[n_gram]

print("score 1: %f" %score_1)
print("score 2: %f" %score_2)

