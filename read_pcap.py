from scapy.all import *
import argparse
import os 

#----------------------------------------------------------------------- Argparse

parser = argparse.ArgumentParser(description='Argparse')
parser.add_argument('-f', '--file')
args = parser.parse_args()

#----------------------------------------------------------------------- Créer + Lire le txt et récup les bonnes requêtes

file_txt = args.file.split(".")[0]+".txt"
os.system('tshark -i - < "'+args.file+'" > "'+file_txt+'"')

lst_co = []

with open(file_txt, "r") as f:
	i=0
	for l in f:
		if "bindRequest" in l and "simple" in l:
			lst_co.append(i)
		i+=1

#----------------------------------------------------------------------- Chercher les requêtes dans le pcap

packets = rdpcap(args.file)
dico_psw = {}

for elem in lst_co:
	ip_src = packets[elem][IP].src
	user_password = ""
	for cara in packets[elem].load:
		if 32 <= cara <= 126 :
			user_password += chr(cara)
		else:
			user_password += "."
	#~ if len(user_password)-user_password.count(".") > 4 :
	for value in dico_psw:
		if dico_psw[value]["user_pwd"] == user_password and dico_psw[value]["src"] == ip_src:
			dico_psw[value]["nb"] += 1
			break
	else:
		dico_psw[str(len(dico_psw))] = {"user_pwd":user_password,"src":ip_src,"nb":1}


for elem in dico_psw:
	print(elem,dico_psw[elem])

