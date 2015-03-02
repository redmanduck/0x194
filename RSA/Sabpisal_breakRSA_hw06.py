#
#  Breaking RSA Encryption for small values of e 
#  Author: ssabpisa
#
from Sabpisal_RSA_hw06 import *

if __name__ == "__main__":
#	1. Generates three sets of public and private keys with e = 3
	
	Keys = []
	plainf = open("message.txt", "r")
	plaintext = plainf.read()
	plainf.close()

	for i in range(3):
		R = RSADuck(e=3)
		private, public = R.get_keys()
		PQPair = R.getPQ()
		Keys.append((private,public, PQPair))

	#	2. Encrypts the given plaintext with each of the three public keys
	R.encrypt_with_publickey()