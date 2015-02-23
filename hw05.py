#!/usr/bin/python
#
from BitVector import *
from math import floor

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

	def encrypt(self,Image):
		i =  0
		j = 0
		EImage = []
		for r in range(len(Image)):
			row = []
			for c in range(len(Image[r])):
				i = (i+1) % 256
				j = (j+self.S[i]) % 256
				temp  =	self.S[i]
				self.S[i] = self.S[j]
				self.S[j] = temp
				k = (self.S[i] + self.S[j]) % 256
				random_byte = self.S[k]

				Xbyte =  Image[r][c] ^ random_byte
				row.append(Xbyte)
			EImage.append(row)
		return EImage

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
	encryptedImage = rc4cipher.encrypt(originalImage)
	RC4.writePPM(originalHead, encryptedImage, "Tiger_enc.ppm")
