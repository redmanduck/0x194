#!/usr/bin/python
#
from BitVector import *
class RC4:
	def __init__(self, key):
		if(len(key) != 16):
			raise Exception("Key not 128 bit")
		bv = BitVector(textstring=key)
		self.K = bv # Key
		self.S = [i for i in range(256)] # State vector
		self.T = [i for i in range(256)] # T vector
		keylen = 16 # 16 bytes
		
		for i in range(256):
			self.T[i] = self.K[i % keylen] 
		
		#Produce initial permutation of S  (KSA algorithm)
		j = 0
		for i in range(256):
			j = (j + self.S[i] + self.T[i]) % 256
			#swap
			temp = self.S[i]
			self.S[i] = self.S[j]
			self.S[j] = temp
		
		del self.T 
	  	
		self.PBS = []	 #pseudorandom byte stream
		i =  0
		j = 0
		while True:
			i = (i+1) % 256
			j = (j+self.S[i]) % 256
			temp  =	self.S[i]
			self.S[i] = self.S[j]
			self.S[j] = temp
			k = (self.S[i] + self.S[j]) % 256
			print self.S[k]

	def encrypt(Image):
		pass

if __name__ == "__main__":
	rc4 = RC4("abcdefghaaaabbbb")	
