#!/usr/bin/python
#
#  Breaking RSA Encryption for small values of e
#  Author: ssabpisa
#
from Sabpisal_RSA_hw06 import *
from solve_pRoot import solve_pRoot

# Crack the message using only Public Key
def crack_message(C1, C2, C3, key1, key2, key3):
	N = key1.n * key2.n * key3.n

	n1 = BitVector(intVal=int(N/key1.n))
	n1_inv = n1.multiplicative_inverse(BitVector(intVal=key1.n))

	n2 = BitVector(intVal=int(N/key2.n))
	n2_inv = n2.multiplicative_inverse(BitVector(intVal=key2.n))

	n3 = BitVector(intVal=int(N/key3.n))
	n3_inv = n3.multiplicative_inverse(BitVector(intVal=key3.n))

	# Compute (a*n1*n1^-1 ...a3*n3*n3^-1) mod N
	a1 = int(C1[0][0:128])
	a2 = int(C2[0][0:128])
	a3 = int(C3[0][0:128])
	S = (a1*int(n1)*int(n1_inv) + a2*int(n2)*int(n2_inv) + a3*int(n3)*int(n3_inv) ) % N
	print S
	print solve_pRoot(3,S)

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

	M = "hllo"

	k1 = KeySet[0]["public"]
	k2 = KeySet[1]["public"]
	k3 = KeySet[2]["public"]

	#	2. Encrypts the given plaintext with each of the three public keys
	a = RSADuck.encrypt_with_publickey(M, k1)
	b = RSADuck.encrypt_with_publickey(M, k2)
	c = RSADuck.encrypt_with_publickey(M, k3)

	atxt = fwrite(a, "personA.enc")
	btxt = fwrite(b, "personB.enc")
	ctxt = fwrite(c, "personC.enc")

	crack_message(a,b,c, k1, k2, k3)