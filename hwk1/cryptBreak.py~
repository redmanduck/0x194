#!/usr/bin/env python

###  cryptBreak.py
###  Suppatach Sabpisal  (ssabpisa@purdue.edu)
###  1/16/15

###  Brute force cryptoanalysis 
###  using DecryptForFun

import sys
from BitVector import *     
from math import pow
import threading



BLOCKSIZE = 16
ENC = "313e3b3273096e146e5d6055655378497c5934433d43310a7b277c6e7a686621622d7e6462656f2c6120683b203d2e7435692f692c692a6762617f7c377d30783c312d37307e3a7631747b17"
PassPhrase = "Hopes and dreams of a million years"
MAX = pow(2, BLOCKSIZE)

def try_key(key):
	numbytes = BLOCKSIZE / 8                                        #(D)

	# Reduce the passphrase to a bit array of size BLOCKSIZE:
	bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                      #(E)
	for i in range(0,len(PassPhrase) / numbytes):                   #(F)
	    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]             #(G)
	    bv_iv ^= BitVector( textstring = textstr )                  #(H)

	# Create a bitvector from the ciphertext hex string:

	encrypted_bv = BitVector( hexstring = ENC )           		#(J)

	if len(key) < numbytes:                                         #(N)
	    key = key + '0' * (numbytes-len(key))                       #(O)

	# Reduce the key to a bit array of size BLOCKSIZE:
	key_bv = BitVector(bitlist = [0]*BLOCKSIZE)                     #(P)
	for i in range(0,len(key) / numbytes):                          #(Q)
	    keyblock = key[i*numbytes:(i+1)*numbytes]                   #(R)
	    key_bv ^= BitVector( textstring = keyblock )                #(S)

	# Create a bitvector for storing the output plaintext bit array:
	msg_decrypted_bv = BitVector( size = 0 )                        #(T)

	# Carry out differential XORing of bit blocks and decryption:
	previous_decrypted_block = bv_iv                                #(U)
	for i in range(0, len(encrypted_bv) / BLOCKSIZE):               #(V)
	    bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]              #(W)
	    temp = bv.deep_copy()                                       #(X)
	    bv ^=  previous_decrypted_block                             #(Y)
	    previous_decrypted_block = temp                             #(Z)
	    bv ^=  key_bv                                               #(a)
	    msg_decrypted_bv += bv                                      #(b)

	outputtext = msg_decrypted_bv.getTextFromBitVector()            #(c)
	return outputtext

def brute(start, end, stopflag):
	bitvec = BitVector(intVal = int(start))
	while(bitvec < BitVector(intVal = int(end))):
		if(stopflag.is_set()):
			print "other thread found the answer!"
			break
		bitvec = BitVector(size = BLOCKSIZE, intVal = (1 + bitvec.intValue()))
		#print("trying " + bitvec.get_text_from_bitvector() + " #" + str(bitvec.intValue()) + " (" + str(bitvec) + ")")
		out = try_key(bitvec.get_text_from_bitvector())
		print "iteration #" + str(bitvec.intValue())
		print out
		if(out.__contains__("Babe Ruth")):
			print "found!"
			print "key" + bitvec.get_text_from_bitvector()
			print "iteration " + bitvec.intValue()
			stopflag.set()
			break


#parallelize bruteforce

stop_all = threading.Event()

t1 = threading.Thread(target=brute, args=(0, MAX/4, stop_all))
t2 = threading.Thread(target=brute, args=(MAX/4, MAX/2, stop_all))
t3 = threading.Thread(target=brute, args=(MAX/2, 3*MAX/4, stop_all))
t4 = threading.Thread(target=brute, args=(3*MAX/4, MAX, stop_all))

t1.daemon = True
t2.daemon = True
t3.daemon = True
t4.daemon = True

t1.start()
t2.start()
t3.start()
t4.start()

t1.join()
t2.join()
t3.join()
t4.join()
