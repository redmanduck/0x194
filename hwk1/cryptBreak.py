#!/usr/bin/env python

###  cryptBreak.py
###  Suppatach Sabpisal  (ssabpisa@purdue.edu)
###  1/16/15
###  homework 1 Q2
###  Brute force cryptoanalysis 
###  using DecryptForFun
###
import sys
from BitVector import *     
from math import pow
import subprocess

BLOCKSIZE = 16
MAX = pow(2, BLOCKSIZE)

##
# try_key will run DecryptForFun
# for provided key and return 
# the decrypted string
def try_key(key):
	f = open('tkey', 'w')
	f.write(key);
	f.close()
	cmd = "DecryptForFun.py encrypted.txt temp < tkey"
	ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	output = ps.communicate()[0]
	f2 = open('temp','r')
	read_data = f2.read()
	f2.close()
	return read_data

## fastbrute
## this is the actual cryptanalysis
##
def fastbrute(start, end):
	b = start
	#start with number 0x0000...0 and add 0x01 at a time until it 
	#exceeds value of `end` 
	while(b < end - 1):
		bitvec = BitVector(size = BLOCKSIZE, intVal = b)
		#get ascii from that number and shove it in DecryptForFun
		out = try_key(bitvec.get_text_from_bitvector())
		print "iteration " + str(b)
		print out
		#increment 1 bit
		b = b + 0b1
		#if it contains what we are looking for, done
		if(out.__contains__("Babe Ruth")):
			print "found!"
			print "key: " + bitvec.get_text_from_bitvector()
			return True



if fastbrute(26720, int(MAX)): 
	sys.exit(0)
fastbrute(0, 26720)
