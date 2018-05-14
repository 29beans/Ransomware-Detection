import sys
import os

ben_dir=sys.argv[1]+"\\"
mal_dir=sys.argv[2]+"\\"
ran_dir=sys.argv[3]+"\\"
n_list=[]


if "-n" in sys.argv:
	i=sys.argv.index("-n")
	i+=1
	while sys.argv[i].isdigit():
		n_list.append(int(sys.argv[i]))
		i+=1
		if i == len(sys.argv):
			break
n_set={}

for n in n_list:
	n_set[n]=set([])

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

def ParseDIR(sample_dir, n_list=n_list):
	file_list=os.listdir(sample_dir)
	for file in file_list:
		fr=open(sample_dir+file, 'r')
		fr.readline()
		data=fr.readlines()
		data=Delete_DLL(data)
		Zw_To_Nt_Translator(data)

		for i in range(len(data)):
			for n in n_list:
				index=i+n
				if index == (len(data)-1 -n):
					break
				n_set[n].add(tuple(data[i:i+n]))
		print("%s  ....... done" %file)
		fr.close()

print("----------------------- benign -------------------------")
ParseDIR(ben_dir)
print("\n----------------------- malware -----------------------")
ParseDIR(mal_dir)
print("\n----------------------- ransom -----------------------")
ParseDIR(ran_dir)

for n in n_list:
	print("%d_gram feature number: %d" %(n, len(n_set[n])))
	f_out=open("G:\\feature_test\\"+str(n)+"_gram_features.txt",'w')
	for feature in n_set[n]:
		f_out.write(str(feature)+"\n")
	f_out.close()