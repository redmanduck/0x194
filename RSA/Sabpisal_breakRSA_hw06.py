#!/usr/bin/python
#
#  Breaking RSA Encryption for small values of e 
#  Author: ssabpisa
#
from Sabpisal_RSA_hw06 import *


# Crack the message using only Public Key
def crack_message(C, public_key):
	# A sends M to B1 encrypted with pub_B1 = C1
	# A sends M to B2 encrypted with pub_B2 = C2
	# A sends M to B3 encrypted with pub_B3 = C3

	# pub_B1..3 has same public exponent
	# different n 

	# we intercepted C1 = M^3 mod n1 ,C2 = M^3 mod n2,C3 = M^3 mod n3

	# we use CRT to calculate M^3 mod N (e=3), N = n1*n2*n3
	
	# N = product of n
	# solve cube root to get M
	pass



if __name__ == "__main__":
#	1. Generates three sets of public and private keys with e = 3	
	KeySet = []
	plainf = open("message.txt", "r")
	plaintext = plainf.read()
	plainf.close()

	for i in range(3):
		R = RSADuck(e=3)
		private, public = R.get_keys()
		PQPair = R.getPQ()
		KeySet.append({ "private": private, "public": public, "pq": PQPair} )

	#	2. Encrypts the given plaintext with each of the three public keys
	a = RSADuck.encrypt_with_publickey("hello", KeySet[0]["public"])
	b = RSADuck.encrypt_with_publickey("hello", KeySet[1]["public"])
	c = RSADuck.encrypt_with_publickey("hello", KeySet[2]["public"])

	atxt = fwrite(a, "personA.enc")
	btxt = fwrite(b, "personB.enc")
	ctxt = fwrite(c, "personC.enc")

	crack_message(atxt, KeySet[0]["public"])