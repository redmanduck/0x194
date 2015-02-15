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
        # generate NxN state matrix
        for i in range(self.state_dim):
            for j in range(self.state_dim):
                self.statearray[j][i] = BitVector(bitstring=self.keybv[WORD*i + BYTE*j : WORD*i + BYTE*(j+1)])

        for i in range(self.state_dim):
            for j in range(self.state_dim):
                print "S"+str(i)+","+str(j), " | ", self.statearray[i][j]


        #the first four w0...dim-1
        for n in range(self.state_dim):
            wn = BitVector(size=0)
            for r in range(self.state_dim):
                wn += self.statearray[r][n]
            self.xkey.append(wn)



        # expand {w0...w3} to {w0...w43}
        for i in range(10):
            self.expand(i)

        print "----------- W0..W43 ----------------"
        for i, wrd in enumerate(self.xkey):
            print 'w'+str(i),
            print _hex(wrd)

    def g(self, x):
        return x

    """
        generate the next set of N words
    """
    def expand(self, offset):
        N = self.state_dim

        # self.xkey[0][i] gives i-th byte of w0
        w0 = self.g(self.xkey[offset*N + (N - 1)]) ^ self.xkey[offset*N]
        print "w" + str(offset*4 + 4) + " = g(w" + str(offset*N + (N - 1)) + ") $ w" + str(offset*N)
        self.xkey.append(w0)

        for i in range(1,N):
            # print "w" + str(offset*4 + 4 + i) + " = w" + str(i-1 + (offset+1)*N) + " $ w" + str(i + offset*N)
            wi = self.g(self.xkey[i-1 + (offset+1)*N]) ^ self.xkey[i + offset*N]
            self.xkey.append(wi)

    def generate_lookup_table(self):
        pass

class AES:
    def __init__(self, key, keylength=128):
        pass
    def encrypt(self, text, keyschedule):
        pass

if __name__ == "__main__":
    key = "lukeimyourfather"
    crypt = AES(key)
    ksch = KeySchedule(key, 128)