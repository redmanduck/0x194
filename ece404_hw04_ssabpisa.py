#!/usr/bin/python
#
import sys
from BitVector import *

BYTE = 8
WORD = 4*BYTE

def _hex(bv):
    return bv.getHexStringFromBitVector()

class KeySchedule:
    bitsize = 0
    state_dim = 4
    statearray = []
    numrounds = {128: 10,
                 192: 12,
                 256: 14}

    xkey = [] # expanded key w0...w43
    lktable = [] #look up table
    keybv = BitVector(size=0)

    def __init__(self, keystr, bitsize):
        self.bitsize = bitsize
        self.state_dim = int(bitsize/32);
        self.statearray = [[None for x in range(self.state_dim)] for x in range(self.state_dim)]
        self.keybv = BitVector(textstring = keystr)
        print "key - " , _hex(self.keybv)
        self.expand_and_fill(0)

    def expand_and_fill(self, offset):
        # generate NxN state matrix
        for i in range(self.state_dim):
            for j in range(self.state_dim):
                self.statearray[j][i] = BitVector(bitstring=self.keybv[WORD*i + BYTE*j : WORD*i + BYTE*(j+1)])

        for i in range(self.state_dim):
            for j in range(self.state_dim):
                print "S"+str(i)+","+str(j), " | ", self.statearray[i][j]


        #the first four w0...w3
        for n in range(self.state_dim):
            wn = BitVector(size=0)
            for i in range(self.state_dim):
                wn += self.statearray[i][n]
            self.xkey.append(wn)

        print "----------- W0..W43 ----------------"
        for i, wrd in enumerate(self.xkey):
            print 'w'+str(i), wrd

    def generate_lookup_table(self):
        pass

class AES:
    def __init__(self, key="lukeimyourfather", keylength=128):
        pass
    def encrypt(self, text, keyschedule):
        pass

if __name__ == "__main__":
    key = "lukeimyourfather"
    crypt = AES(key)
    ksch = KeySchedule(key, 128)