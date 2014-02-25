import commands 
import os
from datetime import datetime, date, time
from pyDes import *

os.system("clear")
print "1. Encryption"
print "2. Decryption\n"
option = input("Enter your Choice:")

if option == 1:
	print "\n1. AES Encryption"
	print "2. DES Encryption"
	print "3. RSA Encryption\n"
	op = input("Enter your Choice :")
	if op == 1:
		print "AES Encrytion Started ..."
		before_time = datetime.now()
		#print "Time before AES Encryption Starts :", before_time
		os.system("python aes.py -e testfile.txt -o testfile_encrytped_AES.txt")
		after_time = datetime.now()
		#print "Time after AES Encryption completes :", after_time
		total_time = after_time - before_time
		print "Total Time conceeded by AES ", total_time

	elif op == 2:
		print "1. Single DES Encryption"
		print "2. Triple DES Encryption\n"
		op2 = input("Enter your Choice:")
		if op2 == 1:
			print "DES Encryption Started..."
			before_time = datetime.now()
			#print "Time before AES Encryption Starts :", before_time
			with file('testfile.txt') as f:
				data = f.read()
			k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
			d = k.encrypt(data)
			with open('testfile_encrypted_Single_DES.txt','w') as f:
				f.write(d)
			after_time = datetime.now()
			#print "Time after DES Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by DES ", total_time
		elif op2 == 2:
			print "DES Encryption Started..."
			before_time = datetime.now()
			#print "Time before AES Encryption Starts :", before_time
			with file('testfile.txt') as f:
				data = f.read()
			k = triple_des("TRIPLE00DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
			d = k.encrypt(data)
			with open('testfile_encrypted_Triple_DES.txt','w') as f:
				f.write(d)
			after_time = datetime.now()
			#print "Time after DES Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by DES ", total_time
		else:
			print "Wrong Option"
			
	elif op == 3:
		print "\n1. Private Key Encryption"
		print "2. Public Key Encryption\n"
		op1=input("Enter your Choice:")
		if op1 == 1:
			print "RSA Private Key Encrytion Started ..."
			before_time = datetime.now()
			#print "Time before RSA Private Key Encryption Starts :", before_time
			os.system("python rsa.py -e testfile.txt -k rsa_privateKey.txt > testfile_encrytped_RSA_private.txt")
			after_time = datetime.now()
			#print "Time after RSA Private Key Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by RSA Private Key Encryption ", total_time
		elif op1 == 2:
			print "RSA Public Key Encrytion Started ..."
			before_time = datetime.now()
			#print "Time before RSA Public Key Encryption Starts :", before_time
			os.system("python rsa.py -e testfile.txt -k rsa_publicKey.txt > testfile_encrytped_RSA_public.txt")
			after_time = datetime.now()
			#print "Time after RSA Public Key Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by RSA Public Key Encryption ", total_time
		else:
			print "Wrong Choice, Exiting ..."
			
	else:
		print "Wrong Option"

elif option == 2:
	print "*** Please perform encryption before proceesing with decryption ***"
	print "\n1. AES Decryption"
	print "2. DES Decryption"
	print "3. RSA Decryption\n"
	op = input("Enter your Choice :")
	if op == 1:
		print "AES Decrytion Started ..."
		before_time = datetime.now()
		#print "Time before AES Encryption Starts :", before_time
		os.system("python aes.py -d testfile_encrytped_AES.txt -o testfile_decrypted_AES.txt ")
		after_time = datetime.now()
		#print "Time after AES Encryption completes :", after_time
		total_time = after_time - before_time
		print "Total Time conceeded by AES Decryption", total_time

	elif op == 2:
		print "1. Single DES Decryption"
		print "2. Triple DES Decryption\n"
		op2 = input("Enter your Choice:")
		if op2 == 1:
			print "Single DES Decryption Started..."
			before_time = datetime.now()
			#print "Time before AES Encryption Starts :", before_time
			with file('testfile_encrypted_Single_DES.txt') as f:
				data = f.read()
			#password = getpass.getpass('Password :')		
			k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
			d = k.decrypt(data)
			with open('testfile_decrypted_Single_DES.txt','w') as f:
				f.write(d)
			after_time = datetime.now()
			#print "Time after DES Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by DES ", total_time
		elif op2 == 2:
			print "Triple DES Decryption Started..."
			before_time = datetime.now()
			#print "Time before AES Encryption Starts :", before_time
			with file('testfile_encrypted_Triple_DES.txt') as f:
				data = f.read()
			#password = getpass.getpass('Password :')		
			k = triple_des("TRIPLE00DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
			d = k.decrypt(data)
			with open('testfile_decrypted_Triple_DES.txt','w') as f:
				f.write(d)
			after_time = datetime.now()
			#print "Time after DES Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by DES ", total_time
		else:
			print "Wrong Option"
	
	elif op == 3:
		print "\n1. Private Key Decryption"
		print "2. Public Key Decryption\n"
		op1=input("Enter your Choice:")
		if op1 == 1:
			print "RSA Private Key Decrytion Started ..."
			before_time = datetime.now()
			#print "Time before RSA Private Key Encryption Starts :", before_time
			os.system("python rsa.py -d testfile_encrytped_RSA_private.txt -k rsa_privateKey.txt > testfile_decrytped_RSA_private.txt")
			after_time = datetime.now()
			#print "Time after RSA Private Key Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by RSA Private Key Decryption ", total_time
		elif op1 == 2:
			print "RSA Public Key Decrytion Started ..."
			before_time = datetime.now()
			#print "Time before RSA Public Key Encryption Starts :", before_time
			os.system("python rsa.py -d testfile_encrytped_RSA_public.txt -k rsa_publicKey.txt > testfile_decrytped_RSA_public.txt")
			after_time = datetime.now()
			#print "Time after RSA Public Key Encryption completes :", after_time
			total_time = after_time - before_time
			print "Total Time conceeded by RSA Public Key Decryption ", total_time
		else:
			print "Wrong Choice, Exiting ..."
			
	else:
		print "Wrong Option"


else :
	print "Yerumai madu"
	
 
