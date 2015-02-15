#!/usr/bin/python
#
import sys
from BitVector import *
import random

BYTE = 8
WORD = 4*BYTE

def _hex(bv):
    return bv.getHexStringFromBitVector()

def _getSubstitute(ib, L):
    if len(ib) > BYTE:
        raise Exception("Input BYTE is not a byte")
    r = int(ib[0:3])
    c = int(ib[4:7])
    return L[r][c]

class KeySchedule:
    bitsize = 0
    state_dim = 4
    statearray = []
    numrounds = {128: 10,
                 192: 12,
                 256: 14}

    xkey = [] # expanded key w0...w43
    LTB = []
    keybv = BitVector(size=0)
    Rcon = []

    def __init__(self, keystr, bitsize, LTB):
        self.bitsize = bitsize
        self.state_dim = int(bitsize/32);
        self.statearray = [[None for x in range(self.state_dim)] for x in range(self.state_dim)]
        self.keybv = BitVector(textstring = keystr)
        self.LTB = LTB

        self.generate_RC()
        print "key - " , _hex(self.keybv)
        # generate NxN state matrix
        for i in range(self.state_dim):
            for j in range(self.state_dim):
                self.statearray[j][i] = BitVector(bitstring=self.keybv[WORD*i + BYTE*j : WORD*i + BYTE*(j+1)])

        print "--------- Input Key Matrix (K) ----------"
        for i in range(self.state_dim):
            for j in range(self.state_dim):
                print _hex(self.statearray[i][j]), " | ",
            print


        #the first four w0...dim-1
        for n in range(self.state_dim):
            wn = BitVector(size=0)
            for r in range(self.state_dim):
                wn += self.statearray[r][n]
            self.xkey.append(wn)



        # expand {w0...w3} to {w0...w43}
        for i in range(10):
            self.expand(i)

        print "----------- Expanded Key (W): 44 Words ----------------"
        for i, wrd in enumerate(self.xkey):
            print 'w'+str(i), "=",
            print _hex(wrd), ",",

    def g(self, w, rnd):

        #check if w is 4 byte
        if(len(w) != 4*BYTE):
            raise Exception("g(word), word is not 4 byte!")
        #perform 1 byte left circular shift
        w << BYTE
        #perform a byte substitution for each byte of the word
        for i in range(4):
            sub = _getSubstitute(w[BYTE*i : BYTE*i + 7], self.LTB)
            #subtitute
            for j in range(BYTE):
                w[j + BYTE*i] = sub[j]

        #XOR bytes with round const

        w = self.Rcon[rnd - 1] ^ w


        return w

    def generate_RC(self):
        modulus = BitVector(bitstring = '100011011')
        n = 8  # indicate we are in GF(2^8)
        RC = [BitVector(intVal=1, size=BYTE)]*10
        #1 -9
        for j in range(1, 10):
            RC[j] =  RC[j-1].gf_multiply_modular(BitVector(intVal=2), modulus, n)

        EMPTYBYTE = BitVector(size=BYTE)
        for i in range(10):
            self.Rcon.append(RC[i] + EMPTYBYTE + EMPTYBYTE + EMPTYBYTE)


    """
        generate the next set of N words
    """
    def expand(self, offset):
        N = self.state_dim
        rnd = offset+1 #round number

        # self.xkey[0][i] gives i-th byte of w0
        w0 = self.g(self.xkey[offset*N + (N - 1)], rnd) ^ self.xkey[offset*N]
        self.xkey.append(w0)

        for i in range(1,N):
            wi = self.g(self.xkey[i-1 + (offset+1)*N], rnd) ^ self.xkey[i + offset*N]
            self.xkey.append(wi)




class AES:
    LTB = []# look up table
    LTB_SIZE = 16
    def __init__(self, key, keylength=128):
        self.generate_lookup_table()

    def encrypt(self, text, keyschedule):
        pass

    def getLookupTable(self):
        return self.LTB

    def generate_lookup_table(self):
        self.LTB = [[BitVector(size=BYTE,intVal=random.randint(0,100)) for x in range(self.LTB_SIZE)] for x in range(self.LTB_SIZE)]

if __name__ == "__main__":
    key = "lukeimyourfather"
    crypt = AES(key)
    ksch = KeySchedule(key, 128, crypt.getLookupTable())