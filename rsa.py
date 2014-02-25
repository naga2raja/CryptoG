#!/usr/bin/python

from random import randint, choice
from math import log
from string import atoi, replace, join
from time import time
import sys

""" Globals to catch command line options """
infile = None
outfile = None
keyfile = None
keylen = None

# print help message
def printHelp():
    print "Usage: ./pyrsa.py [OPTION] [FILE]"
    print "   or: ./pyrsa.py [OPTION] [VALUE]"
    print "Perform pyrsa function specified by OPTION on FILE or VALUE."
    print "  -e, --encrypt\t\tencrypt FILE"
    print "  -d, --decrypt\t\tdecrypt FILE"
    print "  -k, --key\t\tencrypt or decrypt using FILE as key"
    print "  -g, --generate\tgenerate public/private key pair of length" + \
          " VALUE bits"
    print "  -h, --help\t\tprint help message"

# parse command line options
def getOptions():
    global infile, outfile, keyfile, keylen
    if (len(sys.argv) < 2):
        print "pyrsa: too few arguments"
        printHelp()
        sys.exit()
    try:
        for i in range(len(sys.argv)):
            if (sys.argv[i][0] == "-"):
                option = sys.argv[i][1:]
                if (option == "e") or (option == "-encrypt"):
                    infile = sys.argv[i+1]
                elif (option == "d") or (option == "-decrypt"):
                    outfile = sys.argv[i+1]
                elif (option == "k") or (option == "-key"):
                    keyfile = sys.argv[i+1]
                elif (option == "g") or (option == "-generate"):
                    keylen = sys.argv[i+1]
                elif (option == "h") or (option == "-help"):
                    printHelp()
                    sys.exit()
    except:
        print "pyrsa: error reading arguments"
        printHelp()
        sys.exit()

# Return the highest bit that is set in decimal number n
def highbit(n):
    return 2**(int(log(n, 2)))

# Here is a modular exponentiation function that I wrote.  It turns
# out that the built-in function pow(x, y, z) is substantially faster.
# We will use pow(x, y, z) for our purposes, but I will leave  this code
# in to demonstrate how the exponentiation might be done.
def modExp(x, y, n):
    d = 1
    mask = highbit(y)
    # step through the bits of y, the exponent
    while (mask > 0):
        d = (d*d)%n
        # if the mask bit is 1, multiply the result by x mod n
        if (y & mask):
            d = (d*x)%n
        # shift the mask bit
        mask = mask >> 1L
    return d    

# The witness function used in the Miller-Rabin primality test.
# Returns true if a is a witness to the compositeness i.e. non-primality
# of n.  If true is returned, it is guaranteed that n is composite.  However,
# if false is returned, there is a chance that n is only pseudoprime.  We
# account for this in the actual primality test
def witness(a, n):
    # return Composite right away if n is even
    if not n & 1:
        return True
    # solve for n-1 = (2^t)u, where (t >= 1) and u is odd
    num = n - 1
    t = int(log(num,2))
    while (t >= 1):
        if (num % (2**t) == 0):
            break
        t -= 1
    u = num / (2**t)

    test = {}
    test[0] = pow(a, u, n)
    # square
    for i in range(1, t+1):
        test[i] = pow(test[i-1], 2, n)
        if (test[i]==1) and (test[i-1]!=1) and (test[i-1]!=n-1):
            return True
    if (test[t]!=1):
        return True
    return False

# The Miller-Rabin test for primality:
# The function tests witnesses for compositeness in the range of [1, n-1].
# Test is done s times to reduce chance of false positives for primality.
# The probability of a false positive is at most 2^(-s)
def isPrime(n, s):
    if n in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, \
             43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]:
        return True
    for i in range(s):
        a = randint(1, n-1)
        if witness(a, n):
            return False
    return True

# return an N bit prime number.  Since we are using a value of 20 for
# s in the Miller-Rabin test, the probability of a false prime is about
# .000095%
def bigPrime(N):
    p = randint(2**(N-1),2**N)
    while 1:
        # check primality with Miller-Rabin test with certainty of
        # 99.9999046% that p is prime
        if isPrime(p, 20): return p
        p += 1

# Compute the multiplicative inverse of a and b.  This function is
# essentially Euclid's Extended Algorithm.
def inverse(a, b):
    e = a ; phiN = b
    v1 = [1, 0]
    v2 = [0, 1]
    while (a != 0) and (b != 0):
        if (a > b):
            m = a / b
            a %= b
            for i in range(2):
                v1[i] = v1[i] - m*v2[i]
        else:
            m = b / a
            b %= a
            for i in range(2):
                v2[i] = v2[i] - m*v1[i]
    if (a == 1):
        if (v1[0] < 0): return (v1[0]%phiN)
        else: return v1[0]
    else:
        if (v2[0] < 0): return (v2[0]%phiN)
        else: return v2[0]

# Function to generate a public/private key pair.  For N, we take
# the product of two primes of user-specified length.  For e, we use 17,
# a moderate value in the balance between high security and ease of
# computation.  For d, we use Extended Euclidean to find the inverse of
# e mod N
def generateKey(keylen):
    # take a string to append to the begining of the key file names
    firstName = raw_input("\nEnter file identifier (i.e. first name): ")
    publicKey = firstName + "_publicKey.txt"
    privateKey = firstName + "_privateKey.txt"

    # exponentiation value
    e = 17

    # generate public key: (e, N) with N as the product of two large primes
    fp = open(publicKey, "w")
    p = bigPrime(keylen/2)
    q = bigPrime(keylen/2)
    fp.write("----- Begin pyRSA Public Key Block -----\n")
    fp.write(str(e))
    fp.write("\n")
    fp.write(str(p*q))
    fp.write("\n")
    fp.write("----- End pyRSA Public Key Block -----")
    fp.close()

    # generate private key: (e, N) with d as the multiplicative inverse of
    # e mod N
    fp = open(privateKey, "w")
    phiN = (p - 1)*(q - 1)
    d = inverse(e, phiN)
    fp.write("----- Begin pyRSA Private Key Block -----\n")
    fp.write(str(d))
    fp.write("\n")
    fp.write(str(p*q))
    fp.write("\n")
    fp.write("----- End pyRSA Private Key Block -----")
    fp.close()

# Function to convert a character string to a long integer.  We use 8 bits
# per character so the long integer takes no more space than the byte string
# representing the ASCII text
def string2long(s):
    m = 0
    x = len(s) - 1
    # loop backwards through string, for each character add its ASCII value
    # multiplied by its position in the string to the return value
    for char in s:
        m += (256**x)*ord(char)
        x -= 1
    return m

# Function to convert a long integer to a string.
def long2string(m):
    try:
        m = atol(m)
    except:
        pass
    # temporary container for message characters
    letters = []
    # string which will hold the return value
    cleartext = ""
    # treat the long integer as base-256 and loop through, converting each
    # base-256 "digit" to a character
    i = int(log(m, 256))
    while (i >= 0):
        c = m / (256**i)
        letters.append(chr(c))
        m -= c*(256**i)
        i -=1
    # convert the list of characters to a single string
    for l in letters:
        cleartext += l
    return cleartext

# Function to encrypt a character string into a numeric ciphertext.
# KNOWN BUG: when message is too long, i.e. longer than the value of N, this
# function cannot encrypt the message.
# POSSIBLE FIX: in this case, break the message into fixed-sized blocks and
# encrypt each block separately
def encrypt(m):
    # container for the encryption key filename
    global keyfile

    if (keyfile == None):
        print "pyrsa: no encryption key specified.  Use [-k FILE] option.\n"
        sys.exit()

    # convert the character string to a long integer
    message = string2long(m)

    # attempt to take the encryption key data from the key file
    try:
        fp = open(keyfile, "r")
        fp.readline()
        e = int(fp.readline())
        N = int(fp.readline())
        fp.close()
    except:
        print "Cannot read from private key file: ", keyfile
        return None

    # bail out if message is too long
    if (message > N):
        print "Message string is too long.\n"
        return None

    # encrypt the message with modular exponentiation using the values
    # from the encryption key
    message = pow(message, e, N)
    return message

# decrypt a numeric ciphertext and convert it to a plaintext message
def decrypt(m):
    # container for decryption key filename
    global keyfile
    
    if (keyfile == None):
        print "pyrsa: no decryption key specified.  Use [-k FILE] option.\n"
        sys.exit()

    # attempt to take the decryption key data from the key file    
    try:
        fp = open(keyfile, "r")
        fp.readline()
        d = int(fp.readline())
        N = int(fp.readline())
        fp.close()
    except:
        print "Cannot read from key file: ", keyfile
        return None

    # decrypt message using modular exponentiation
    message = pow(int(m), d, N)

    return long2string(message)

# Main Function: get command line options and perform RSA functions based
# on options
def main():
    global infile, outfile, keyfile, keylen

    # get command line options
    getOptions()
    if infile:
        m = open(infile, "r")
        message = m.readlines()
        m.close()
        message = join(message)
        print encrypt(message)
    elif outfile:
        c = open(outfile, "r")
        ciphertext = c.readlines()
        c.close()
        ciphertext = join(ciphertext)
        print "Decrypted text:\n", decrypt(ciphertext)
    elif keylen:
        generateKey(int(keylen))
        
if __name__ == "__main__":
    main()

