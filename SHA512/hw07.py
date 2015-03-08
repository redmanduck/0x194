#!/usr/bin/python
#SHA512
from BitVector import *

def Ch(x,y,z):
	bvxinv = ~BitVector(intVal = x)
	return (x & y) ^ (int(bvxinv) & z)

def Maj(x,y,z):
	return (x & y) ^ (x & z) ^ (y & z)

def ROTR(x, n):
	if x < 0:
		print x
		raise Exception("why is x negative")
	bv = BitVector(intVal = x)
	bv >> n
	return int(bv)

def SHR(x, n):
	return x >> n

def sum0(x):
	return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x, 39)
	
def sum1(x):
	return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x, 41)

def add64(x,y):
	return (int(x) + int(y)) % (2**64)

def sig0(x):
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7)

def sig1(x):
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6)


K = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

if __name__ == '__main__':
	# 1024 bit message block
	# 512 bit block cipher using msg block as key

	# (1) the SHA512 compression function
	# (2) the SHA-512 message schedule

	message = 'abc'

	h0 = 0x6a09e667f3bcc908
	h1 = 0xbb67ae8584caa73b
	h2 = 0x3c6ef372fe94f82b
	h3 = 0xa54ff53a5f1d36f1
	h4 = 0x510e527fade682d1
	h5 = 0x9b05688c2b3e6c1f
	h6 = 0x1f83d9abfb41bd6b
	h7 = 0x1f83d9abfb41bd6b

	bv = BitVector(textstring = message)
	length = bv.length()

	bv1 = bv + BitVector(bitstring="1")
	length1 = bv1.length()
	# l + 1 + k == 896 mod 1024
	# k = 896 - (l+1) (mod 1024)
	howmanyzeros = (896 - length1) % 1024
	zerolist = [0] * howmanyzeros
	bv2 = bv1 + BitVector(bitlist = zerolist)
	bv3 = BitVector(intVal = length, size = 128)
	bv4 = bv2 + bv3

	if(len(bv4) % 1024 != 0):
		raise Exception("padded message not multiple of 1024")

	padmesg = int(bv4)

	print "Padded Hex Message" , hex(padmesg)

	H = []

	words = [None] * 80 # Message schedule Wj
	
	#populate W
	for i in range(0, bv4.length(), 1024):
		block = bv4[i:i+1024]
		words[0:16] = [int(block[i:i+64]) for i in range(0,1024,64)]
		#Apply SHA compression function (f) to update registers
		for j in range(16, 80):
			#Compute Wj
			# temp = add64(words[x-7], sig1(words[x-2]))
			# words[x] = add64(add64(words[x-16], sig0(words[x-15])), temp)
			words[j] = (sig1(words[j-2]) + words[j-7] + sig0(words[j-15]) + words[j-16]) % ( 2**64)

	# iterate through the plaintext N times (1024 block size)
	for i in range(0, bv4.length(), 1024):
		a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7


		# Apply SHA compression to update h0..h7
		for j in range(80):
			print "register at t =", (j-1)
			print hex(a),hex(b),hex(c),hex(d)
			print hex(e),hex(f),hex(g),hex(h)
			print "-------------------------------"

			Wj = words[j]
			Kj = K[j];
			T1 = (h + sum1(e) + Ch(e,f,g) + Kj + Wj) % (2**64)
			T2 = ((sum0(a)) + (Maj(a,b,c))) % (2**64)
			h = g
			g = f
			f = e
			e = (d + T1) % (2**64)
			d = c
			c = b
			b = a
			a = (T1 + T2) % (2**64)

		h0,h1,h2 = (a + h0) % (2**64), (b + h1)% (2**64), (c + h2)% (2**64)
		h3,h4,h5,h6,h7 = (d + h3)% (2**64), (e + h4)% (2**64), (f + h5)% (2**64), (g + h6)% (2**64), (h + h7)% (2**64)

	print hex(h0)
	print hex(h1)
	print hex(h2)