import sys
import os
import operator
import random
import pandas as pd
import numpy as np
import csv
from scipy.sparse import lil_matrix

# sample_dir_ben=sys.argv[1]+"/"
# sample_dir_mal=sys.argv[2]+"/"
# sample_dir_ran=sys.argv[3]+"/"

sample_dir_ben="G:\\ben_NT_syscall(manual)\\"
sample_dir_mal="G:\\mal_NT_syscall(filtered)\\"
sample_dir_ran="G:\\ran_NT_syscall(filtered3)\\"

weight_path="C:\\exp_data\\RTFRD\\CF-NCF_anal\\"
feature_header_path="C:\\exp_data\\feature_set\\"
file_seq_path="C:\\exp_data\\feature_set\\"
CSV_path="C:\\exp_data\\feature_set\\output\\"

arg_num=len(sys.argv)-1
# threshold_num cannot be zero!! 

n_index=-1
ben_th_index=-1
mal_th_index=-1
ran_th_index=-1
k=0

n_list=[]
ben_th_list=[]
mal_th_list=[]
ran_th_list=[]

IsBen=True
IsMal=True
IsRan=True

# check the status of cmd arguments
# if missed family exists, 
# fill up the threshold list of that family with 0 (for identification)
print()

if "-t" in sys.argv:
	TrainingApplied=True
	print("-------------------- Training Phase applied --------------------\n")
else:
	TrainingApplied=False

if "-c" in sys.argv:
	ClassificationApplied=True
	print("-------------------- Classification Phase applied --------------------\n")
else:
	ClassificationApplied=False

if "-s" in sys.argv:
	SplitApplied=True
else:
	SplitApplied=False

if "-k" in sys.argv:
	k=int(sys.argv[sys.argv.index("-k")+1])

if "-n" in sys.argv:
	n_index=sys.argv.index("-n")

if "-b" in sys.argv:
	ben_th_index=sys.argv.index("-b")
else:
	ben_th_list.append('0')
	IsBen=False

if "-m" in sys.argv:
	mal_th_index=sys.argv.index("-m")
else:
	mal_th_list.append('0')
	IsMal=False

if "-r" in sys.argv:
	ran_th_index=sys.argv.index("-r")
else:
	ran_th_list.append('0')
	IsRan=False

# parse sys.argv and fill up with parameter list

arg_index=0

if n_index != -1:
	arg_index=n_index+1
	while sys.argv[arg_index].isdigit():
		n_list.append(int(sys.argv[arg_index]))
		arg_index+=1
		if arg_index > arg_num:
			break

if ben_th_index != -1:
	arg_index=ben_th_index+1
	while sys.argv[arg_index].isdigit():
		ben_th_list.append(sys.argv[arg_index])
		arg_index+=1
		if arg_index > arg_num:
			break

if mal_th_index != -1:
	arg_index=mal_th_index+1
	while sys.argv[arg_index].isdigit():
		mal_th_list.append(sys.argv[arg_index])
		arg_index+=1
		if arg_index > arg_num:
			break

if ran_th_index != -1:
	arg_index=ran_th_index+1
	while sys.argv[arg_index].isdigit():
		ran_th_list.append(sys.argv[arg_index])
		arg_index+=1
		if arg_index > arg_num:
			break

n_num=len(n_list)
max_n=max(n_list)

# for system argument check
print("n_list: ", n_list)
print("k_value: %d" %k)
print("ben_th_list: ", ben_th_list)
print("mal_th_list: ", mal_th_list)
print("ran_th_list: ", ran_th_list)

training_dir_ben="G:/training/benign_training(manual)/"
training_dir_mal="G:/training/malware_training/"
training_dir_ran="G:/training/ransom_training/"

classification_output_dir="G:/classification_result/"
classification_output_dir_CF_NCF="G:/classification_result/CF_NCF/"

training_list_dir_ben=training_dir_ben+"training_list/"
training_list_dir_mal=training_dir_mal+"training_list/"
training_list_dir_ran=training_dir_ran+"training_list/"

cf_chunk_dir_ben=training_dir_ben+"chunk_list/"
cf_chunk_dir_mal=training_dir_mal+"chunk_list/"
cf_chunk_dir_ran=training_dir_ran+"chunk_list/"

train_index_dir_ben="C:\\exp_data\\RTFRD\\training_index\\ben\\"
train_index_dir_mal="C:\\exp_data\\RTFRD\\training_index\\mal\\"
train_index_dir_ran="C:\\exp_data\\RTFRD\\training_index\\ran\\"

cf_chunk_index_dir_ben="C:\\exp_data\\RTFRD\\cf_chunk_index\\ben\\"
cf_chunk_index_dir_mal="C:\\exp_data\\RTFRD\\cf_chunk_index\\mal\\"
cf_chunk_index_dir_ran="C:\\exp_data\\RTFRD\\cf_chunk_index\\ran\\"

total_exp_count=0

chunk_list_ben=[]
chunk_list_mal=[]
chunk_list_ran=[]

cf_chunk_index_list_ben=[]
cf_chunk_index_list_mal=[]
cf_chunk_index_list_ran=[]

total_ben_api_count=0
total_mal_api_count=0
total_ran_api_count=0

total_ben_file_num=0
total_mal_file_num=0
total_ran_file_num=0

ben_TP=[0 for j in range(n_num)]
ben_TN=[0 for j in range(n_num)]
ben_FP=[0 for j in range(n_num)]
ben_FN=[0 for j in range(n_num)]		

mal_TP=[0 for j in range(n_num)]
mal_TN=[0 for j in range(n_num)]
mal_FP=[0 for j in range(n_num)]
mal_FN=[0 for j in range(n_num)]

ran_TP=[0 for j in range(n_num)]
ran_TN=[0 for j in range(n_num)]
ran_FP=[0 for j in range(n_num)]
ran_FN=[0 for j in range(n_num)]

ben_score=[[] for i in range(n_num)]
mal_score=[[] for i in range(n_num)]
ran_score=[[] for i in range(n_num)]

ben_sig_dic=[{} for i in range(n_num)]
mal_sig_dic=[{} for i in range(n_num)]
ran_sig_dic=[{} for i in range(n_num)]

#Preparation for splitting each of file list into 10-fold chunks

def InitializeScore(ben_score, mal_score, ran_score):
	for i in range(n_num):
		ben_score[i]=0
		mal_score[i]=0
		ran_score[i]=0

def InitializeDic(ben_sig_dic, mal_sig_dic, ran_sig_dic):
	for i in range(n_num):
		ben_sig_dic[i]={}
		mal_sig_dic[i]={}
		ran_sig_dic[i]={}

def InitializeTFPN():
	for i in range(n_num):
		ben_TP[i], ben_TN[i], ben_FP[i], ben_FN[i]=0,0,0,0
		mal_TP[i], mal_TN[i], mal_FP[i], mal_FN[i]=0,0,0,0
		ran_TP[i], ran_TN[i], ran_FP[i], ran_FN[i]=0,0,0,0

def SplitSamplesToChunks(k, sample_dir, training_list_dir, cf_chunk_dir, class_label):
	
	file_list=os.listdir(sample_dir)
	random.shuffle(file_list)
	chunk_size=int(len(file_list)/k)
	chunk_list=[]
	training_chunk=[]
	#Generate k-fold chunks for each of sample file list

	for i in range(k-1):
		chunk_list.append(file_list[i*chunk_size:(i+1)*chunk_size])
	chunk_list.append(file_list[(k-1)*chunk_size:])

	# Backup randomly created chunk list in each of text file in training directory

	for i in range(k):
		if not os.path.isdir(cf_chunk_dir):
			os.mkdir(cf_chunk_dir)

		chunk_out=open(cf_chunk_dir+"chunk_list_"+class_label+"_"+str(i)+".txt",'w')
		
		for file in chunk_list[i]:
			chunk_out.write(file+"\n")
		chunk_out.close()
	
	# Make training chunk for each of testing chunk[i]
	# And save them as files
	# training_chunk = entire file list - testing chunk(chunk_list)

	for i in range(k):
		training_chunk.append(list(set(file_list) - set(chunk_list[i])))

		if not os.path.isdir(training_list_dir):
			os.mkdir(training_list_dir)

		train_chunk_out=open(training_list_dir+"training_list_"+str(i)+".txt",'w')

		for file_name in training_chunk[i]:		
			train_chunk_out.write(file_name+"\n")
		train_chunk_out.close()

def Delete_DLL(target_list):
	result_list=[]
	for line in target_list:
		if '\t' not in line:
			continue
		api=line.split()[0]
		result_list.append(api)
	return result_list

def CleanUp(target_list):
	for element in target_list:
		if '\t' not in element:
			target_list.remove(element)

def Zw_To_Nt_Translator(target_list):
	for i in range(len(target_list)):
		Zw_starter=target_list[i]
		if Zw_starter.startswith('Zw'):
			target_list[i]='Nt'+Zw_starter[2:]

def CF_NCF_Weight(n, feature_header, class_label, weight_path=weight_path):
	file_name=class_label+"_"+str(n)+"_gram_CF_NCF.csv"
	with open(feature_header, 'r') as f:
		feature_list=f.read().split()

	w_data=pd.read_csv(weight_path+file_name, header=None).as_matrix()
	CF_weight=w_data[0]
	NCF_weight=w_data[1]
	col_num=w_data.shape[1]
	print("weight vector column num: %d" %col_num)

	weight={key:value for key, value in zip(feature_list, [CF_weight[i] * (1 - NCF_weight[i]) for i in range(col_num)])}
	return weight

def ApplyWeight(weight_vector, target_vector):

	for feature in target_vector.keys():
		target_vector[feature]*=weight_vector[str(feature)]

# training phase for 10-fold cross validation
def Training(k, n_list, training_list_dir, training_dir, sample_dir, threshold_list, class_label):

	#f os.path.isfile(training_dir+str(n)+"_gram/"+"training"+str(i+1)+"_"+threshold_list[l]+"%.txt")
	#print("threshold: ",threshold_list)
	max_n=max(n_list)
	n_num=len(n_list)

	training_list=[]

	# Weight Vector Construction
	weight_vector={ key:value for key, value in zip(n_list, [dict() for n in n_list])}
	for n in n_list:
		feature_header_fname=feature_header_path+str(n)+"_gram_features.txt"
		weight_vector[n]=CF_NCF_Weight(n, feature_header_fname, class_label)

	# Restore the training lists created in earlier training phase
	# Do not update it with randomization
	# Too complicated to analysize the result

	for i in range(k):
		f=open(training_list_dir+"training_list_"+str(i)+".txt",'r')
		training_list.append(f.read().split())

	for i in range(k):
		total_file_num=0
		total_gram_count=0

		n_gram_dic_list={key: value for key, value in zip(n_list, [dict() for i in n_list])}

	# n-gram training phase for each of training chunk
		for name in training_list[i]:  # for each of files 
			f=open(sample_dir+name, 'r')
			f.readline()
			data=f.readlines()
			total_file_num+=1

			temp_dic_list={key: value for key, value in zip(n_list, [dict() for i in n_list])}
			# Translate API-DLL raw data into API_seq data
			data_seq=Delete_DLL(data)
			#print(data_seq)
			# Convert all prefix Zw' of system call to prefix 'Nt'
			Zw_To_Nt_Translator(data_seq)
			normal_factor=1000000/(len(data_seq)-max_n+1) # for normalization of each of training sample w.r.t the size of syscall log
			total_gram_count+=(len(data_seq)-max_n+1)

			# parse appearance count of each n-gram
			# And, record them in temporary dictionary (for later normalization of n-gram count of each file)
			# Ignore the last n-grams of n's (except the biggest one) for convenience

			for j in range(len(data_seq)-max_n+1):   
				for n in n_list:
					n_gram=tuple(data_seq[j:j+n])
					temp_dic=temp_dic_list[n]

					if n_gram in temp_dic:
						temp_dic[n_gram]+=1
					else:
						temp_dic[n_gram]=1

			# Restore the saved n-gram count of each file into the n_gram_matrix
			# After normalization of each n-gram count w.r.t. each file's log size
			for n in n_list:
				temp_dic=temp_dic_list[n]
				n_gram_dic=n_gram_dic_list[n]

				for n_gram in list(temp_dic.keys()):
					if n_gram in n_gram_dic:
						n_gram_dic[n_gram]+=int(temp_dic[n_gram]*normal_factor)
					else:
						n_gram_dic[n_gram]=int(temp_dic[n_gram]*normal_factor)

			f.close()

		# Apply Weight after n-gram dictionarization completed
		for n in n_list:
			ApplyWeight(weight_vector[n], n_gram_dic_list[n])

		#print(n_gram_matrix)
		#print("sum: %d" %sum(n_gram_matrix.values()))
		sorted_result_list={}

		# Write training files into appropriate directory path
		for n in n_list:
			n_gram_dic=n_gram_dic_list[n]
			sorted_result_list[n]=sorted(n_gram_dic.items(), key=operator.itemgetter(1), reverse=True)
			norm_total_gram_count=(1000000-max_n+1)*total_file_num

			if not os.path.isdir(training_dir+str(n)+"_gram"):
				os.mkdir(training_dir+str(n)+"_gram")

			if not os.path.isdir(training_dir+str(n)+"_gram/training_total"):
				os.mkdir(training_dir+str(n)+"_gram/training_total")
			out=open(training_dir+str(n)+"_gram/training_total/"+"training_total_"+str(i+1)+".txt", 'w')

			sorted_result=sorted_result_list[n]

			for l in range(len(sorted_result)):
				out.write(str(sorted_result[l][0]) + "\t" + str(sorted_result[l][1]/norm_total_gram_count) + "\n")
			out.write("\nTotal File num: %d\n" %total_file_num)
			out.write("Total gram num: %d\n" %len(sorted_result))
			out.write("Total gram count: %d\n" %total_gram_count)
			out.write("Normalized total gram count: %d\n" %norm_total_gram_count)
			out.close()

			# prune the trained result by the threshold percentage of total # of individual api 

			for th in threshold_list:
				out=open(training_dir+str(n)+"_gram/"+"training"+str(i+1)+"_"+th+"%.txt", 'w')
				cut_index=ReturnCutIndex(sorted_result, th, norm_total_gram_count)  # Cut sorted result by accumulative percentage(threshold) of system call
				cut_result=sorted_result[:cut_index]
				
				# counting the total gram count in signature list 
				cut_gram_total=0
				for m in range(len(cut_result)):
					cut_gram_total+=cut_result[m][1]

				for m in range(len(cut_result)):
					out.write(str(cut_result[m][0]) + "\t" + "%.10f\n" %(cut_result[m][1]/cut_gram_total))

				#print(training_dir.split('/')[1] + " sig_total: %d" %sig_total)
				out.write("\nTotal File num: %d\n" %total_file_num)
				out.write("Total gram num: %d\n" %len(cut_result))
				out.write("Total gram count: %d\n" %cut_gram_total)
				out.close()

		print("------------------------- Training %d done -------------------------" %(i+1))		

			

# Cut target_list by accumulative percentage(threshold) of gram count			
def ReturnCutIndex(target_list, acc_threshold, total_count):
	sum=0
	for i in range(len(target_list)):
		sum+=target_list[i][1]
		if (sum/total_count)*100 >= float(acc_threshold):
			return i

def RuleOutWhiteList(sign_dic1, sign_dic2):
	sign_gram_set1=set(sign_dic1.keys())
	sign_gram_set2=set(sign_dic2.keys())

	white_list=sign_api_set1 & sign_api_set2

	for gram in sign_gram_set1:
		if gram in white_list:
			del(sign_dic1[gram])
	for gram in sign_gram_set2:
		if gram in white_list:
			del(sign_dic2[gram])

def EqualizeNumOfSignList(sign_dic1, sign_dic2):
	sorted_result_dic1=sorted(sign_dic1.items(), key=operator.itemgetter(1), reverse=True)
	sorted_result_dic2=sorted(sign_dic2.items(), key=operator.itemgetter(1), reverse=True)
	key_list1=[]
	key_list2=[]

	for i in range(len(sorted_result_dic1)):
		key_list1.append(sorted_result_dic1[i][0])

	for i in range(len(sorted_result_dic2)):
		key_list2.append(sorted_result_dic2[i][0])

	if len(sorted_result_dic1) > len(sorted_result_dic2):
		target_key_list=key_list1[len(sorted_result_dic2):]
		DeletePairFromDic(sign_dic1,target_key_list)

	elif len(sorted_result_dic1) < len(sorted_result_dic2):
		target_key_list=key_list2[len(sorted_result_dic1):]
		DeletePairFromDic(sign_dic2,target_key_list)

def DeletePairFromDic(source_dic, target_key_list):
	for i in range(len(target_key_list)):
		del(source_dic[target_key_list[i]])

def DecideFamily(ben_score, mal_score, ran_score):
	cmp_list=[ben_score, mal_score, ran_score]
	max_score=max(cmp_list)
	max_index=cmp_list.index(max_score)

	if max_index == 0:
		return "benign"
	elif max_index == 1:
		return "malware"
	elif max_index == 2:
		return "ransom"
	else:
		return "undefined"

def MakeTrainedVector(i, n_list, training_dir, threshold, vector):
	for n in n_list:
		index=n_list.index(n)
		fr=open(training_dir+str(n)+"_gram/"+"training"+str(i+1)+"_"+threshold+"%.txt",'r')
		data=fr.readlines()
		fr.close()

		for line in data:
			if '\t' not in line:
				break
			key_value=line.split('\t')
			vector[index][key_value[0]]=float(key_value[1])

def Classifier(f_output, chunk_list, sample_dir, class_label, ben_score, mal_score, ran_score):

	global total_exp_count
	
	for file in chunk_list:
		total_exp_count+=1
		fr=open(sample_dir+file,'r')
		fr.readline()
		data=fr.readlines()
		fr.close()
		data=Delete_DLL(data)
		Zw_To_Nt_Translator(data)

		InitializeScore(ben_score, mal_score, ran_score)
		CalculateScore(file, data, chunk_list, sample_dir)
		EvaluateResult(f_output, file, class_label)

	for j in range(n_num):
		f_output[j].write("\n")

def CountRowsAndColumns(file_name):
	with open(file_name,'r', encoding="utf-8") as f:
		data=csv.reader(f)
		row_num=len(f.readlines())
		f.seek(0)
		col_num=len(next(data))
		f.seek(0)
	return row_num, col_num

def SparseMatrix(file_name, row_num, col_num, CSV_dir=CSV_path):

	with open(CSV_dir+file_name,'r',encoding="utf-8") as f:
		data=csv.reader(f)

		sparse_matrix=lil_matrix((row_num,col_num), dtype=np.int32)

		row_idx=0
		for row in data:
			sparse_matrix[row_idx, :]=row
			row_idx+=1

	return sparse_matrix

def ChunkIdxToFileName(file_seq_path=file_seq_path):
	file_name=file_seq_path+"file_seq.txt"
	idxToFileNameDic={}

	with open(file_name, 'r') as f:
		seq_data=f.readlines()

		for i, line in enumerate(seq_data):
			idxToFileNameDic[i]=line.split()[0]
	return idxToFileNameDic

def FeatureIdxToString(n_list=n_list, feature_path=feature_header_path, CSV_dir=CSV_path):
	map_dic={key: value for key, value in zip(n_list, [{} for n in n_list])}

	for n in n_list:
		file_name=feature_path+str(n)+"_gram_features.txt"
		with open(file_name, 'r') as f:
			features=f.read().split()

			for idx, feature_name in enumerate(features):
				map_dic[n][idx]=feature_name
	return map_dic

def ClassifierWithCSV(f_output, cf_chunk_index_list, csv_matrix, idx_to_feature_name, idx_to_file, class_label, ben_score, mal_score, ran_score):
	
	global total_exp_count
	for idx in cf_chunk_index_list:
		total_exp_count+=1
		InitializeScore(ben_score, mal_score, ran_score)
		CalculateScoreWithCSV(csv_matrix, cf_chunk_index_list, idx, idx_to_feature_name)
		EvaluateResult(f_output, idx_to_file[idx], class_label)

	for j in range(n_num):
		f_output[j].write("\n")
		

def CalculateScore(file_name, data, chunk_list, sample_dir):

	for j in range(len(data)-max_n+1):
		for n_index in range(n_num):
			n=n_list[n_index]
			target=str(tuple(data[j:j+n]))

			if target in ben_sig_dic[n_index]:
				ben_score[n_index]+=ben_sig_dic[n_index][target]**2

			if target in mal_sig_dic[n_index]:
				mal_score[n_index]+=mal_sig_dic[n_index][target]**2

			if target in ran_sig_dic[n_index]:
				ran_score[n_index]+=ran_sig_dic[n_index][target]**2

def CalculateScoreWithCSV(csv_matrix, cf_chunk_index_list, chunk_idx, idx_to_feature_name):

	for n_index in range(n_num):
		n=n_list[n_index]
		sample_log=csv_matrix[n][chunk_idx,:].toarray()[0][:-1]
		# print(sample_log)
		for f_idx, f_count in enumerate(sample_log):
			if f_count == 0:
				continue

			target=idx_to_feature_name[n][f_idx]

			if target in ben_sig_dic[n_index]:
				ben_score[n_index]+=f_count*(ben_sig_dic[n_index][target]**2)

			if target in mal_sig_dic[n_index]:
				mal_score[n_index]+=f_count*(mal_sig_dic[n_index][target]**2)

			if target in ran_sig_dic[n_index]:
				ran_score[n_index]+=f_count*(ran_sig_dic[n_index][target]**2)

def EvaluateResult(f_output, file_name, answer):

	for j in range(n_num):
		decision=DecideFamily(ben_score[j], mal_score[j], ran_score[j])
		if decision == answer:
			if answer == "benign":
				ben_TP[j]+=1
				mal_TN[j]+=1
				ran_TN[j]+=1
				f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "BENIGN", "TRUE", ben_score[j], mal_score[j], ran_score[j]))
			elif answer == "malware":
				ben_TN[j]+=1
				mal_TP[j]+=1
				ran_TN[j]+=1
				f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "MALWARE", "TRUE", ben_score[j], mal_score[j], ran_score[j]))
			elif answer == "ransom":
				ben_TN[j]+=1
				mal_TN[j]+=1
				ran_TP[j]+=1
				f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "RANSOM", "TRUE", ben_score[j], mal_score[j], ran_score[j]))				
		else:
			if answer == "benign":
				if decision == "malware":
					ben_FN[j]+=1
					mal_FP[j]+=1
					ran_TN[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "MALWARE","FALSE", ben_score[j], mal_score[j], ran_score[j]))
				elif decision == "ransom":
					ben_FN[j]+=1
					mal_TN[j]+=1
					ran_FP[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "RANSOM", "FALSE", ben_score[j], mal_score[j], ran_score[j]))
			elif answer == "malware":
				if decision == "benign":
					ben_FP[j]+=1
					mal_FN[j]+=1
					ran_TN[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "BENIGN", "FALSE", ben_score[j], mal_score[j], ran_score[j]))
				elif decision == "ransom":
					ben_TN[j]+=1
					mal_FN[j]+=1
					ran_FP[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "RANSOM", "FALSE", ben_score[j], mal_score[j], ran_score[j]))
			elif answer == "ransom":
				if decision == "benign":
					ben_FP[j]+=1
					mal_TN[j]+=1
					ran_FN[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "BENIGN", "FALSE", ben_score[j], mal_score[j], ran_score[j]))
				elif decision == "malware":
					ben_TN[j]+=1
					mal_FP[j]+=1
					ran_FN[j]+=1
					f_output[j].write("%s\t%s\t%s\t%f\t%f\t%f\n" %(file_name, "MALWARE", "FALSE", ben_score[j], mal_score[j], ran_score[j]))

def RecordResults(f_output, j, class_label, result, i, TFPN ,TP, TN, FP, FN):

	try:
		precision=100*TP/(TP+FP)
		recall=100*TP/(TP+FN)
		acc=100*(TP+TN)/TFPN
	except ZeroDivisionError:
		print("Exp %d %s: Zero Division Error!!" %(i+1,class_label))
		print("TP is definitely 0 and FP or FN is 0")
		f_output[j].write("Exp %d %s: Zero Division Error!! TP is definitely 0 and FP or FN is 0\n" %(i, class_label))
		result.append([-1,-1,-1])
	else:
		f_output[j].write("Exp %d %s precision: %f\trecall: %f\tacc: %f\n" %(i+1, class_label, precision, recall, acc))
		print("Exp %d %s precision: %f\trecall: %f\tacc: %f" %(i+1, class_label, precision, recall, acc))
		result.append([precision, recall, acc])

def RecordSummary(f_output, class_label, result_trace, index):

	for j in range(n_num):
		for l in range(k):
			f_output[j].write("%10s%7.4f" %(class_label+" pre: ", result_trace[j][l][index][0]))
		f_output[j].write("\n")
		for l in range(k):	
			f_output[j].write("%10s%7.4f" %(class_label+" rec: ", result_trace[j][l][index][1]))
		f_output[j].write("\n")
		for l in range(k):
			f_output[j].write("%10s%7.4f" %(class_label+" acc: ", result_trace[j][l][index][2]))
		f_output[j].write("\n\n")

def RestoreChunkList():
	# Restore the chunk lists randomly created from latest training phase

	for i in range(k):
		if IsBen:
			read_ben_chunk_list=open(cf_chunk_dir_ben+"chunk_list_ben_"+str(i)+".txt",'r')
			chunk_list_ben.append(read_ben_chunk_list.read().split())
			read_ben_chunk_list.close()
		if IsMal:
			read_mal_chunk_list=open(cf_chunk_dir_mal+"chunk_list_mal_"+str(i)+".txt",'r')
			chunk_list_mal.append(read_mal_chunk_list.read().split())
			read_mal_chunk_list.close()
		if IsRan:
			read_ran_chunk_list=open(cf_chunk_dir_ran+"chunk_list_ran_"+str(i)+".txt",'r')
			chunk_list_ran.append(read_ran_chunk_list.read().split())
			read_ran_chunk_list.close()

def RestoreCfChunkIndexOfCSV(k=k):
	for i in range(k):
		if IsBen:
			with open(cf_chunk_index_dir_ben+"cf_chunk_index_list_"+str(i)+".txt",'r') as f:
				cf_chunk_index_list_ben.append(list(map(int,f.read().split())))
		if IsMal:
			with open(cf_chunk_index_dir_mal+"cf_chunk_index_list_"+str(i)+".txt",'r') as f:
				cf_chunk_index_list_mal.append(list(map(int,f.read().split())))
		if IsRan:
			with open(cf_chunk_index_dir_ran+"cf_chunk_index_list_"+str(i)+".txt",'r') as f:
				cf_chunk_index_list_ran.append(list(map(int,f.read().split())))

def Classification(k, n_list, ben_threshold, mal_threshold, ran_threshold):

	global total_exp_count
	
	b_str, m_str, r_str = "", "", ""

	if IsBen:
		b_str="benign,"
	if IsMal:
		m_str="malware,"
	if IsRan:
		r_str="ransomware"

	result_trace=[]
	f_output=[]
	
	for n in n_list:
		if not os.path.isdir(classification_output_dir+str(n)+"_gram/"):
			os.mkdir(classification_output_dir+str(n)+"_gram/")

	for i in range(n_num): 
		f_output.append(open(classification_output_dir+str(n_list[i])+"_gram/"+"cf_result_"+ben_threshold+"_"+mal_threshold+"_"+ran_threshold+".txt",'w'))
		f_output[i].write("="*100+"\n\n")
		f_output[i].write("This file shows the result of classification among %s %s %s\n\n" %(b_str, m_str, r_str))
		
		result_trace.append([])

		if IsBen:
			f_output[i].write("benign threshold: %d\n" %int(ben_threshold))
		if IsMal:
			f_output[i].write("malware threshold: %d\n" %int(mal_threshold))
		if IsRan:
			f_output[i].write("ransomware threshold: %d\n\n" %int(ran_threshold))
		f_output[i].write("="*100+"\n\n")

	# classification process start!!!
	for i in range(k):	
		total_exp_count=0

		InitializeDic(ben_sig_dic, mal_sig_dic, ran_sig_dic)
		InitializeTFPN()

		for j in range(n_num):
			f_output[j].write("-"*20+" Experiment "+str(i+1)+"-"*20 +"\n\n")

		# read training file of corresponding threshold
		# translate benign, ransom, malware training file into dictionary structure..

		if IsBen:
			MakeTrainedVector(i, n_list, training_dir_ben, ben_threshold, ben_sig_dic)
		if IsMal:
			MakeTrainedVector(i, n_list, training_dir_mal, mal_threshold, mal_sig_dic)
		if IsRan:
			MakeTrainedVector(i, n_list, training_dir_ran, ran_threshold, ran_sig_dic)

		# Read each family's chunk file[i] and classification start

		if IsBen:
			Classifier(f_output, chunk_list_ben[i], sample_dir_ben, "benign", ben_score, mal_score, ran_score)
		if IsMal:
			Classifier(f_output, chunk_list_mal[i], sample_dir_mal, "malware", ben_score, mal_score, ran_score)
		if IsRan:
			Classifier(f_output, chunk_list_ran[i], sample_dir_ran, "ransom", ben_score, mal_score, ran_score)

		# n-th classification experiment ended
		# Save the result into file
		print("-------------- Exp %d total result (ben: %s mal: %s ran: %s) --------------\n" %(i+1, ben_threshold, mal_threshold, ran_threshold))

		for j in range(n_num):
			ben_TFPN=ben_TP[j]+ben_TN[j]+ben_FP[j]+ben_FN[j]
			mal_TFPN=mal_TP[j]+mal_TN[j]+mal_FP[j]+mal_FN[j]
			ran_TFPN=ran_TP[j]+ran_TN[j]+ran_FP[j]+ran_FN[j]

			if total_exp_count != max(ben_TFPN, mal_TFPN, ran_TFPN):
				print("------------------------- Experiment %d error -------------------------" %(i+1))
				print ("Total exp count: %d\t TFPN: %d" %(total_exp_count, max(ben_TFPN, mal_TFPN, ran_TFPN)))
			
			f_output[j].write("\n")
			f_output[j].write("-------------------- Exp %d total result --------------------\n" %(i+1))
			
			print("-n: %d\n" %n_list[j])
			print("TFPN: ", ben_TFPN, mal_TFPN, ran_TFPN)
			print()
			print("TP: %d TN: %d FP: %d FN: %d" %(ben_TP[j],ben_TN[j],ben_FP[j],ben_FN[j]))
			print("TP: %d TN: %d FP: %d FN: %d" %(mal_TP[j],mal_TN[j],mal_FP[j],mal_FN[j]))
			print("TP: %d TN: %d FP: %d FN: %d\n" %(ran_TP[j],ran_TN[j],ran_FP[j],ran_FN[j]))

			result=[]

			if IsBen:
				RecordResults(f_output, j, "ben", result, i, ben_TFPN, ben_TP[j], ben_TN[j], ben_FP[j], ben_FN[j])
			else:
				result.append([0,0,0])
				
			if IsMal:
				RecordResults(f_output, j, "mal", result, i, mal_TFPN, mal_TP[j], mal_TN[j], mal_FP[j], mal_FN[j])
			else:
				result.append([0,0,0])

			if IsRan:
				RecordResults(f_output, j, "ran", result, i, ran_TFPN, ran_TP[j], ran_TN[j], ran_FP[j], ran_FN[j])
			else:
				result.append([0,0,0])
		
			f_output[j].write("\n\n")

			result_trace[j].append(result)
			print()

	# print the final integrated result of k-fold cross validation
	
	for j in range(n_num):
		f_output[j].write("\n\n--------------------------------- Integrated Result --------------------------------\n")
		for l in range(k):
			f_output[j].write("%10dth%7s" %(l+1, " "))
		f_output[j].write("\n")	

	if IsBen:
		RecordSummary(f_output, "ben", result_trace, 0)
	if IsMal:
		RecordSummary(f_output, "mal", result_trace, 1)
	if IsRan:
		RecordSummary(f_output, "ran", result_trace, 2)

	for j in range(n_num):
		f_output[j].close()	

def ClassificationWithCSV(k, n_list, ben_threshold, mal_threshold, ran_threshold, CSV_dir=CSV_path):

	global total_exp_count
	
	b_str, m_str, r_str = "", "", ""

	if IsBen:
		b_str="benign,"
	if IsMal:
		m_str="malware,"
	if IsRan:
		r_str="ransomware"

	result_trace=[]
	f_output=[]
	csv_matrix={}
	idx_to_file=ChunkIdxToFileName()
	idx_to_feature_name=FeatureIdxToString()

	for n in n_list:
		if not os.path.isdir(classification_output_dir_CF_NCF+str(n)+"_gram/"):
			os.mkdir(classification_output_dir_CF_NCF+str(n)+"_gram/")	
		file_name=str(n)+"_gram_vector.csv"
		row_num, col_num = CountRowsAndColumns(CSV_dir+file_name)
		csv_matrix[n]=SparseMatrix(file_name, row_num, col_num)

	print("CSV Loading Done!")

	for i in range(n_num): 
		f_output.append(open(classification_output_dir_CF_NCF+str(n_list[i])+"_gram/"+"cf_result_"+ben_threshold+"_"+mal_threshold+"_"+ran_threshold+".txt",'w'))
		f_output[i].write("="*100+"\n\n")
		f_output[i].write("This file shows the result of classification among %s %s %s\n\n" %(b_str, m_str, r_str))
		
		result_trace.append([])

		if IsBen:
			f_output[i].write("benign threshold: %d\n" %int(ben_threshold))
		if IsMal:
			f_output[i].write("malware threshold: %d\n" %int(mal_threshold))
		if IsRan:
			f_output[i].write("ransomware threshold: %d\n\n" %int(ran_threshold))
		f_output[i].write("="*100+"\n\n")

	# classification process start!!!
	for i in range(k):	
		total_exp_count=0

		InitializeDic(ben_sig_dic, mal_sig_dic, ran_sig_dic)
		InitializeTFPN()

		for j in range(n_num):
			f_output[j].write("-"*20+" Experiment "+str(i+1)+"-"*20 +"\n\n")

		# read training file of corresponding threshold
		# translate benign, ransom, malware training file into dictionary structure..

		if IsBen:
			MakeTrainedVector(i, n_list, training_dir_ben, ben_threshold, ben_sig_dic)
		if IsMal:
			MakeTrainedVector(i, n_list, training_dir_mal, mal_threshold, mal_sig_dic)
		if IsRan:
			MakeTrainedVector(i, n_list, training_dir_ran, ran_threshold, ran_sig_dic)

		# Read each family's chunk file[i] and classification start

		if IsBen:
			ClassifierWithCSV(f_output, cf_chunk_index_list_ben[i], csv_matrix, idx_to_feature_name, idx_to_file, "benign", ben_score, mal_score, ran_score)
		if IsMal:
			ClassifierWithCSV(f_output, cf_chunk_index_list_mal[i], csv_matrix, idx_to_feature_name, idx_to_file, "malware", ben_score, mal_score, ran_score)
		if IsRan:
			ClassifierWithCSV(f_output, cf_chunk_index_list_ran[i], csv_matrix, idx_to_feature_name, idx_to_file, "ransom", ben_score, mal_score, ran_score)

		# n-th classification experiment ended
		# Save the result into file
		print("-------------- Exp %d total result (ben: %s mal: %s ran: %s) --------------\n" %(i+1, ben_threshold, mal_threshold, ran_threshold))

		for j in range(n_num):
			ben_TFPN=ben_TP[j]+ben_TN[j]+ben_FP[j]+ben_FN[j]
			mal_TFPN=mal_TP[j]+mal_TN[j]+mal_FP[j]+mal_FN[j]
			ran_TFPN=ran_TP[j]+ran_TN[j]+ran_FP[j]+ran_FN[j]

			if total_exp_count != max(ben_TFPN, mal_TFPN, ran_TFPN):
				print("------------------------- Experiment %d error -------------------------" %(i+1))
				print ("Total exp count: %d\t TFPN: %d" %(total_exp_count, max(ben_TFPN, mal_TFPN, ran_TFPN)))
			
			f_output[j].write("\n")
			f_output[j].write("-------------------- Exp %d total result --------------------\n" %(i+1))
			
			print("n: %d\n" %n_list[j])
			print("TFPN: ", ben_TFPN, mal_TFPN, ran_TFPN)
			print()
			print("TP: %d TN: %d FP: %d FN: %d" %(ben_TP[j],ben_TN[j],ben_FP[j],ben_FN[j]))
			print("TP: %d TN: %d FP: %d FN: %d" %(mal_TP[j],mal_TN[j],mal_FP[j],mal_FN[j]))
			print("TP: %d TN: %d FP: %d FN: %d\n" %(ran_TP[j],ran_TN[j],ran_FP[j],ran_FN[j]))

			total_accuracy=100*(ben_TP[j]+mal_TP[j]+ran_TP[j])/total_exp_count
			f_output[j].write("Exp %d Total Accuracy: %.4f (n: %d)\n" %(i+1, total_accuracy, n_list[j]))
			print("Exp %d Total Accuracy: %f (n: %d)" %(i+1, total_accuracy, n_list[j]))
			result=[]

			if IsBen:
				RecordResults(f_output, j, "ben", result, i, ben_TFPN, ben_TP[j], ben_TN[j], ben_FP[j], ben_FN[j])
			else:
				result.append([0,0,0])
				
			if IsMal:
				RecordResults(f_output, j, "mal", result, i, mal_TFPN, mal_TP[j], mal_TN[j], mal_FP[j], mal_FN[j])
			else:
				result.append([0,0,0])

			if IsRan:
				RecordResults(f_output, j, "ran", result, i, ran_TFPN, ran_TP[j], ran_TN[j], ran_FP[j], ran_FN[j])
			else:
				result.append([0,0,0])
		
			f_output[j].write("\n\n")

			result_trace[j].append(result)
			print()

	# print the final integrated result of k-fold cross validation
	
	for j in range(n_num):
		f_output[j].write("\n\n--------------------------------- Integrated Result --------------------------------\n")
		for l in range(k):
			f_output[j].write("%10dth%7s" %(l+1, " "))
		f_output[j].write("\n")	

	if IsBen:
		RecordSummary(f_output, "ben", result_trace, 0)
	if IsMal:
		RecordSummary(f_output, "mal", result_trace, 1)
	if IsRan:
		RecordSummary(f_output, "ran", result_trace, 2)

	for j in range(n_num):
		f_output[j].close()	
# training phase start
# First, split total samples into each of k-chunks for k-fold cross validation
# For one time. Use the below function as least as possible. (It randomizes cross-fold samples)

if SplitApplied:
	if IsBen:
		SplitSamplesToChunks(k, sample_dir_ben, training_list_dir_ben, cf_chunk_dir_ben, "ben")
	if IsMal:
		SplitSamplesToChunks(k, sample_dir_mal, training_list_dir_mal, cf_chunk_dir_mal, "mal")
	if IsRan:
		SplitSamplesToChunks(k, sample_dir_ran, training_list_dir_ran, cf_chunk_dir_ran, "ran")

if TrainingApplied:
	if IsBen:
		print("------------------------- Benign Training -------------------------")
		Training(k, n_list, training_list_dir_ben, training_dir_ben, sample_dir_ben, ben_th_list, "ben")
	if IsMal:
		print("------------------------- Malware Training -------------------------")
		Training(k, n_list, training_list_dir_mal, training_dir_mal, sample_dir_mal, mal_th_list, "mal")
	if IsRan:
		print("------------------------- Ransom Training -------------------------")
		Training(k, n_list, training_list_dir_ran, training_dir_ran, sample_dir_ran, ran_th_list, "ran")

# classification phase start
if ClassificationApplied:
	# RestoreChunkList()
	RestoreCfChunkIndexOfCSV() # For Classification Using CSV log file
	for ben_th in ben_th_list:
		for mal_th in mal_th_list:
			for ran_th in ran_th_list:
				print("------------------------- Classification start (ben: %d mal: %d ran: %d) --------------------------" %(int(ben_th), int(mal_th), int(ran_th)))
				ClassificationWithCSV(k, n_list, ben_th, mal_th, ran_th)