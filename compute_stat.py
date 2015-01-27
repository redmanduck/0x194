#!/usr/bin/python
#
### Compute Diffusion and Confusion

import sys
from DES_sabpisal import *

def invert(num):
	if(num == 0):
		return 1
	return 0

def main():
    ## write code that prompts the user for the key
    ## and then invokes the functionality of your implementation

    userkey = get_encryption_key()

    original = "peter.txt"
    original_diffuse = "peter2.txt"

    f0 = open(original, "rb")
    bv1 = BitVector(textstring = f0.read())

    for j in range(64):
    	#how many bit to change
    	bv1[j] = invert(bv1[j]);

    f = open(original_diffuse, "wb")
    f.write(bv1.get_text_from_bitvector())
    f.close()
    f0.close()

    a1 = des(None, original, "temp", userkey)
    a2 = des(None, original_diffuse, "temp", userkey)

    print "A1: ", a1
    print "A2: ", a2

    diff = a1 ^ a2
    print "Diff: ", diff
    print "Bits Different: ", diff.count_bits()
    print "Percent Diffusion: ", 100*diff.count_bits()/64.00

if __name__ == "__main__":
    main()
