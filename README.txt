#############################################################################
# 				  ABOUT					    #
#############################################################################

Author:   Nagaraja. T
Date:     15th January, 2014
Verion:   1.0.1
License:  GPL
Homepage: https://github.com/naga2raja/CryptoG


CryptoG is simple Encryption/Decryption program using AES,DES and RSA algorithms.
This CryptoG is written purely in python. 

The following types of Encryption & Decryption is available using CryptoG

1) AES 
     - AES Encryption & Decryption
2) DES
     - Single DES Encryption & Decryption
     - Triple DES Encryption & Decryption
3) RSA
     - Private Key Encryption & Decryption     
     - Public Key Encryption & Decryption
     


#############################################################################
# 				PRE-REQUISITES				    #
#############################################################################

CryptoG program requires pyDES package (Zip available along with the package). Please install it using the following command before running CryptoG.

	$ unzip pyDes-2.0.1.zip 
	$ cd pyDes-2.0.1/
	$ sudo python setup.py install 

#############################################################################
# 			         Credits				    #
#############################################################################

 - Todd Whiteman:     	For pyDes package
 - Brandon Sterne: 	For his excellent writting on RSA
 - Godwin Ponsam:       For making me to write this program

#############################################################################
# 				CryptoG usage				    #
#############################################################################

CryptoG performs both Encryption and Decryption. The program accepts the input file named "testfile.txt". Encryption is performed before decryption. 

******************  AES ALGORITHM (Encrytion and Decryption) ***************
AES Encryption:
(Input file : testfile.txt)

$ python cryptog.py

1. Encrytion
2. Decryption

Enter your choice : 1
1. AES Encryption
2. DES Encryption
3. RSA Encryption

Enter your choice : 1
AES Encrytion Started ...
Encrypting file: testfile.txt
Encryption complete.
Total Time conceeded by AES  0:00:10.877200

After encryption is done, a file called testfile_encrytped_AES.txt will be created. This file contains the encrypted contents of testfile.txt.

AES Decryption:
(Input file : testfile_encrytped_AES.txt) #An encrypted file where encryption done using AES.

$ python cryptog.py

1. Encrytion
2. Decryption

Enter your choice : 2
*** Please perform encryption before proceesing with decryption ***

1. AES Decryption
2. DES Decryption
3. RSA Decryption

Enter your Choice :1
AES Decrytion Started ...
Decrypting file: testfile_encrytped_AES.txt
Decryption complete.
Total Time conceeded by AES Decryption 0:00:11.241573

After decyption is done, a file called testfile_decrypted_AES.txt will be created with original text.

******************************** DES ALGORITHM (single & triple DES) ***************************

Single DES Encryption:
(input file : testfile.txt)
1. Encryption
2. Decryption

Enter your Choice:1

1. AES Encryption
2. DES Encryption
3. RSA Encryption

Enter your Choice :2
1. Single DES Encryption
2. Triple DES Encryption

Enter your Choice:1
DES Encryption Started...
Total Time conceeded by DES  0:00:05.459710

fter encryption is done, a file called testfile_encrytped_single_DES.txt will be created. This file contains the single DES encrypted contents of testfile.txt.

Single DES Decryption:
(input file : testfile_encrytped_single_DES.txt )
1. Encryption
2. Decryption

Enter your Choice:2
*** Please perform encryption before proceesing with decryption ***

1. AES Decryption
2. DES Decryption
3. RSA Decryption

Enter your Choice :2
1. Single DES Decryption
2. Triple DES Decryption

Enter your Choice:1
Single DES Decryption Started...
Total Time conceeded by DES  0:00:05.441380

### This format is same for Triple DES Encryption and Decryption algorithm

******************************************* RSA ALGORITHM (private key & public key algorithm) *******************

Private Key Encryption:
(input file : testfile.txt)

1. Encryption
2. Decryption

Enter your Choice:1

1. AES Encryption
2. DES Encryption
3. RSA Encryption

Enter your Choice :3

1. Private Key Encryption
2. Public Key Encryption

Enter your Choice:1
RSA Private Key Encrytion Started ...
Total Time conceeded by RSA Private Key Encryption  0:01:55.643147

Private Key Decryption:
(input file : testfile_encrypted_RSA_private.txt)

1. Encryption
2. Decryption

Enter your Choice:2
*** Please perform encryption before proceesing with decryption ***

1. AES Decryption
2. DES Decryption
3. RSA Decryption

Enter your Choice :3

1. Private Key Decryption
2. Public Key Decryption

Enter your Choice:1
RSA Private Key Decrytion Started ...
Total Time conceeded by RSA Private Key Decryption  0:01:30.029714

### This steps are same for RSA Public Key encryption also.


