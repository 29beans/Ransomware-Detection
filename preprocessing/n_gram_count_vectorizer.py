import sys
import os
import csv

ben_dir=sys.argv[1]+"\\"
mal_dir=sys.argv[2]+"\\"
ran_dir=sys.argv[3]+"\\"
feature_set_dir="C:\\python_code\\feature_set\\"
output_dir="C:\\python_code\\feature_set\\output2\\"
n_list=[]
ben_label, mal_label, ran_label = 0, 1, 2
ben_file_list, mal_file_list, ran_file_list = (os.listdir(sys.argv[i]) for i in range(1,4))

if "-n" in sys.argv:
	i=sys.argv.index("-n")
	i+=1
	while sys.argv[i].isdigit():
		n_list.append(int(sys.argv[i]))
		i+=1
		if i == len(sys.argv):
			break
print("n: ", n_list)
n_feature_set={key:value for (key, value) in zip(n_list, [[] for n in n_list])}
n_hash_table={key: value for (key, value) in zip(n_list, [{} for n in n_list])}

def HashFunc(feature):
	return hash(feature)

def ConstructFeatureSet():
	for n in n_list:
		with open(feature_set_dir+str(n)+"_gram_features.txt",'r') as fr:
			data=fr.readlines()
			err_cnt=0
			for f_index, line in enumerate(data):
				feature=line[:-1]
				if (feature.count("'")/2) != n:
					# print("n: %d, feature: %s" %(n, feature))
					err_cnt+=1
				f_hash= HashFunc(feature)
				n_feature_set[n].append(feature) # strip '\n'
				
				if f_hash not in n_hash_table[n]:
					n_hash_table[n][f_hash]={}
				n_hash_table[n][f_hash][feature]=f_index
			print("n: %d err_cnt: %d" %(n,err_cnt))
		print("------------- %d ConstructFeatureSet completed -------------" %n)

	for n in n_list:
		print("%d feature set size: %d" %(n, len(n_feature_set[n])))
		print("%d hash table size: %d" %(n, len(n_hash_table[n])))

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
			target_list[i]='Nt'+Zw_starter[2:]

def VectorIndex(n, n_gram):
	return n_feature_set[n].index(n_gram)

def HashIndex(n, n_gram):
	try:
		return n_hash_table[n][HashFunc(n_gram)][n_gram]
	except:
		print("error hash: %d from %s" %(HashFunc(n_gram), n_gram))
		if HashFunc(n_gram) not in n_hash_table[n]:
			print("hash not found!")
		else:
			print("hash found!")

def PreProcessingDir(sample_dir, file_list, class_label, n_list=n_list):
	result_vector={key:value for (key, value) in zip(n_list,[[[0 for j in range(len(n_feature_set[n]))] for i in file_list] for n in n_list])}
	# Count all n-grams of all files in directory and,
	# Save it as dictionary-list structure
	f_idx=0
	for file in file_list:
		with open(sample_dir+file, 'r') as fr:
			fr.readline()
			data=fr.readlines()
			data=Delete_DLL(data)
			Zw_To_Nt_Translator(data)
		
			data_len=len(data)
			for i in range(data_len):
				for n in n_list:
					end_idx=i+n-1
					if end_idx > (data_len-1):
						continue
					if len(tuple(data[i:i+n])) != n:
						print("n: %d, tuple: " %n, tuple(data[i:end_idx+1]))
						print("hash: %d" %HashIndex(n, str(tuple(data[i:end_idx+1]))))
					
					result_vector[n][f_idx][HashIndex(n, str(tuple(data[i:end_idx+1])))]+=1
					

					# print("index: %d, data_len: %d" %(index, data_len))
		f_idx+=1
		print("%s ........ done" %file)

	for n in n_list:
		with open(output_dir+str(n)+"_gram_vector.csv",'a',encoding="utf-8", newline='') as fr:
			wr=csv.writer(fr)
			for row in result_vector[n]:
				row.append(class_label)
				wr.writerow(row)

# PreProcessing start
ConstructFeatureSet()
print("----------------------- benign -------------------------")
PreProcessingDir(ben_dir, ben_file_list, ben_label)
print("\n----------------------- malware -----------------------")
PreProcessingDir(mal_dir, mal_file_list, mal_label)
print("\n----------------------- ransom -----------------------")
PreProcessingDir(ran_dir, ran_file_list, ran_label)
