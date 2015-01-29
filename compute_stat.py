#!/usr/bin/python
#
### Compute Diffusion and Confusion

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

    original = "peter.txt"
    original_diffuse = "peter2.txt"

    f0 = open(original, "rb")
    bv1 = BitVector(textstring = f0.read())

    bv1[0] = invert(bv1[0]);

    f = open(original_diffuse, "wb")
    f.write(bv1.get_text_from_bitvector())
    f.close()
    f0.close()

    a1 = DESS.des(DESS.MODE_ENC, original, "temp", userkey)
    a2 = DESS.des(DESS.MODE_ENC, original_diffuse, "temp", userkey)


    print "================= WITH PROVIDED S-BOX ===================="
    print "Cipher Text (original plain text): ", a1[0:15]
    print "Cipher Text (plain text 1 bit changed): ", a2[0:15]

    diff = a1 ^ a2

    print "Bits Different: ", diff.count_bits()
    print "Percent Diffusion: ", 100*diff.count_bits()/64.00

    print "================ WITH DIFFERENT S-BOX ==================="
    randomly_generate_sbox("s-box-generated.txt")

    DESS.populate_sbox("s-box-generated.txt")

    a1 = DESS.des(DESS.MODE_ENC, original, "temp", userkey)
    a2 = DESS.des(DESS.MODE_ENC, original_diffuse, "temp", userkey)

    print "Cipher Text (original plain text): ", a1
    print "Cipher Text (plain text 1 bit changed): ", a2

    diff = a1 ^ a2

    print "Bits Different: ", diff.count_bits()
    print "Percent Diffusion: ", 100*diff.count_bits()/64.00

    print "====================================="

if __name__ == "__main__":
    main()
