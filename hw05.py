#!/usr/bin/python
#
from BitVector import *
from math import floor
from copy import deepcopy

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


	def reset_randombyte():
		self.rbytes = []

	def generate_randombyte_stream(self, Image):
		i =  0
		j = 0
		self.rbytes = []
		S = deepcopy(self.S)
		for r in range(len(Image)):
			row = []
			for c in range(len(Image[r])):
				i = (i+1) % 256
				j = (j+S[i]) % 256
				temp  =	S[i]
				S[i] = S[j]
				S[j] = temp
				k = (S[i] + S[j]) % 256
				random_byte = S[k]
				self.rbytes.append(random_byte)

	def encrypt(self,Image, gen_random=True):
		EImage = []
		
		if(gen_random):
			self.generate_randombyte_stream(Image)

		i = 0
		for r in range(len(Image)):
			row = []
			for c in range(len(Image[r])):
				random_byte = self.rbytes[i]
				i += 1

				Xbyte =  Image[r][c] ^ random_byte 
				row.append(Xbyte)
			EImage.append(row)
		return EImage

	def decrypt(self, Image):
		return self.encrypt(Image, False)


	@staticmethod
	def loadPPM(filename):
		headers = []
		image = []
		f  = open(filename , "r")
		data = f.readlines()
		for i in range(len(data)):
			curline = data[i]
			if i < 5:
				#header
				headers.append(data[i])
				continue
			row = []
			for j in range(len(curline)):
				row.append(ord(curline[j]))
			image.append(row)
		return headers, image

	@staticmethod
	def writePPM(headlist, Image, filename):
		f = open(filename, "wb")
		f.writelines(headlist)
		for i in range(len(Image)):
			for j in range(len(Image[i])):
				f.write(chr(Image[i][j]))

		f.close()

if __name__ == "__main__":
	originalHead, originalImage = RC4.loadPPM("Tiger2.ppm")
	rc4cipher = RC4("abcdefghaaaabbbb")
	print "encrypting.."
	encryptedImage = rc4cipher.encrypt(originalImage)
	RC4.writePPM(originalHead, encryptedImage, "Tiger_enc.ppm")
	print "decrypting.."
	decryptedImage = rc4cipher.encrypt(encryptedImage, False)
	RC4.writePPM(originalHead, decryptedImage, "Tiger_dec.ppm")

	assert(encryptedImage != decryptedImage)
	assert(encryptedImage != originalImage)
	assert(decryptedImage == originalImage)