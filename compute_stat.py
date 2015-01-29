#!/usr/bin/python
#
### Compute Diffusion and Confusion
###
### 
### DES ECE4O4 
### Suppatach Sabpisal (ssabpisa@purdue.edu)
### Homework 2 Q2
### 
###
###
import sys
import DES_sabpisal as DESS
import random
from BitVector import *

def randomly_generate_sbox(fname):
	f  = open(fname, "w")
	for box in range(8):
		for col in range(4):
			for row in range(16):
				f.write(str(random.randrange(0,15)) + " ")
			f.write("\n")
		f.write("\n")
	f.close()

def invert(num):
	if(num == 0):
		return 1
	return 0

def main():
    ## write code that prompts the user for the key
    ## and then invokes the functionality of your implementation
    
    print "Computing Statistics"

    userkey = DESS.get_encryption_key()

    original = "message.txt"
    original_diffuse = "message_bitmod.txt"

    f0 = open(original, "rb")
    plaintext  = f0.read()
    

    print "================= Q1 OBSERVING DIFFUSION ===================="

    a1 = DESS.des(DESS.MODE_ENC, original, "temp", userkey)
    print "Cipher Text (original plain text): ", a1[0:15], "..."

    ## Change one bit
    sum = 0
    for K in range(5):
        bv1 = BitVector(textstring = plaintext)
        wh = random.randrange(0, bv1.size)
        bv1[wh] = invert(bv1[wh]);

        f = open(original_diffuse, "wb")
        f.write(bv1.get_text_from_bitvector())
        f.close()
        f0.close()

        a2 = DESS.des(DESS.MODE_ENC, original_diffuse, "temp", userkey)

        print "Cipher Text (1 random bit changed): ", a2[0:15], "..."

        diff = a1 ^ a2

        print "Bits Diff: ", diff.count_bits()
        sum += diff.count_bits()
    print "Average Diff : ", sum/5

    print "================= Q3 OBSERVING CONFUSION ===================="


    keylist = []

    for trykey in range(5):
        keyname = "keybit" + str(trykey) + ".key"
        f = open(keyname, "w")
        bkey = BitVector(textstring = "sherlock")
        wh = random.randrange(0, bkey.size) #what bit to change
        bkey[wh] = invert(bkey[wh])
        f.write(bkey.get_text_from_bitvector())
        f.close()
        keylist.append(keyname)

    print "Cipher Text (key = sherlock): ", a1[0:15], "..."
    diffsum = 0
    for K in keylist:
        customkey = DESS.get_encryption_key_from_file(K)
        a2 = DESS.des(DESS.MODE_ENC, original, "temp", customkey)

        diff = a1 ^ a2
    
        diffbit = diff.count_bits()
        diffsum += diffbit

        print "Cipher Text (keyfile = " + K + "): ", a2[0:15], "..."
        print "Diff : ", diffbit
        print "----------------------------"
    print "Average Bit Difference : ", diffsum/len(keylist)

    print "================ Q2 WITH RANDOMLY GENERATED S-BOX ==================="

    print "Cipher Text (original plain text): ", a1[0:15], "..."
    sum = 0
    randomly_generate_sbox("s-box-generated.txt")
    DESS.populate_sbox("s-box-generated.txt")

    a1 = DESS.des(DESS.MODE_ENC, original, "temp", userkey)
    print "Cipher Text (plain text, new sbox): ", a1[0:15], "..."

    for K in range(6):
        bv1 = BitVector(textstring = plaintext)
        wh = random.randrange(0, bv1.size)
        bv1[wh] = invert(bv1[wh]);

        f = open(original_diffuse, "wb")
        f.write(bv1.get_text_from_bitvector())
        f.close()
        f0.close()

        a2 = DESS.des(DESS.MODE_ENC, original_diffuse, "temp", userkey)

        print "Cipher Text (1 random bit changed): ", a2[0:15], "..."

        diff = a1 ^ a2

        print "Bits Diff: ", diff.count_bits()
    
        sum += diff.count_bits()

    print "Average Bit Diff : ", sum/6

    print "====================================="

if __name__ == "__main__":
    main()
