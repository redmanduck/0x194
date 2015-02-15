#!/usr/bin/python
#
#
#  ECB implementation of AES
#  only tested with 128 bit key size
#
#

import sys
from BitVector import *
import random
from copy import deepcopy

BYTE = 8
WORD = 4*BYTE
MODULUS = BitVector(bitstring = '100011011') #AES irreducible polynomial in GF(2^8)


def _hex(bv):
    return bv.getHexStringFromBitVector()
def _text(bv):
    return bv.get_text_from_bitvector()
def lrotate(l,n):
    return l[n:] + l[:n]

def print_state(M):
    # Assume square matrices
    print "--------- State Array ----------"
    for i in range(len(M)):
        for j in range(len(M)):
            print _hex(M[i][j]), " | ",
        print
"""
    get subbyte frm lookup table (16x16)
    given input byte
"""
def _getSubstitute(ib, L):
    if len(ib) > BYTE:
        raise Exception("Input BYTE to find sub is not a byte")
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
        print

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
        n = 8  # indicate we are in GF(2^8)
        RC = [BitVector(intVal=1, size=BYTE)]*10
        #1 -9
        for j in range(1, 10):
            RC[j] =  RC[j-1].gf_multiply_modular(BitVector(intVal=2), MODULUS, n)

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

    def get_key_for_round(self, i):
        return self.xkey[i*4] + self.xkey[i*4+1] + self.xkey[i*4+2]  + self.xkey[i*4+3]


class AES:
    LTB = []# look up table
    LTB_SIZE = 16
    ENCRYPT = 'encrypt'
    DECRYPT = 'decrypt'

    state_dim = 4

    def __init__(self, key, keylength=128, mode=ENCRYPT):
        self.generate_lookup_table()
        self.mode = mode

    def state_array_from_bv128(self, txtbv):
        if(len(txtbv) != 128):
            raise Exception("Text BitVector is not 128 bit!")
        M = [[None for x in range(self.state_dim)] for x in range(self.state_dim)]
        for i in range(self.state_dim):
            for j in range(self.state_dim):
                M[j][i] = BitVector(bitstring=txtbv[WORD*i + BYTE*j : WORD*i + BYTE*(j+1)])

        print_state(M)

        return M

    def encrypt(self, textbv, keyschedule):
        textbv = AES.add_round_key(textbv , keyschedule.get_key_for_round(0))
        state_r = self.state_array_from_bv128(textbv)
        for i in range(10):
            state_r = self.round_process(state_r, keyschedule.get_key_for_round(i+1))

        return self.reconstruct_column_wise(state_r)

    def reconstruct_column_wise(self, SR):
        concat = BitVector(size=0)
        for c in range(len(SR)):
            for r in range(len(SR)):
                concat = concat + SR[r][c]

        return concat

    @staticmethod
    def add_round_key(bv, roundkey_bv):
        if len(bv) != len(roundkey_bv):
            raise Exception("Round Key and BV len not equal!")
        return roundkey_bv ^ bv

    def round_process(self, state_r, roundkey_bv):
        if(state_r == None):
            raise Exception("State Array is None")

        # SUB BYTE
        state_r = AES.subbyte(self.getLookupTable(), state_r)
        # SHIFT ROW
        state_r = AES.shiftrows(state_r)
        # MIX COLUMN
        state_r = AES.mixcolumns(state_r)


        # add round KEY
        keybytes = []
        for i in range(16):
            keybytes.append(roundkey_bv[i*8:i*8+8])
        g=0
        for r in range(len(state_r)):
            for c in range(len(state_r)):
                xorkey = keybytes[g]
                state_r[r][c] = AES.add_round_key(state_r[r][c], xorkey)
                g = g +1

        return state_r

    @staticmethod
    def shiftrows(M):
        print "--------- Shift Row ----------"
        N = len(M)
        MF = deepcopy(M)
        M0 = deepcopy(M)

        for r in range(1,N):
            for c in range(N):
                cx = c + r
                if(cx > (N-1)):
                    #wrap around
                    over = cx - (N-1)
                    cx = over - 1

                print "(%d, %d) -> (%d, %d)" % (r,c, r, cx)
                MF[r][c] = M0[r][cx]

        return MF

    @staticmethod
    def subbyte(LTB, state_r):
        for i in range(len(state_r)):
            for j in range(len(state_r)):
                cand = _getSubstitute(state_r[i][j], LTB)
                state_r[i][j] = cand

        return state_r

    @staticmethod
    def mixcolumns(S):
        M = deepcopy(S)

        """
            Encryption

            [ 2 3 1 1
              1 2 3 1    x   [S] = [S*]
              1 1 2 3
              3 1 1 2 ]

            Decryption

            [ E B D 9
              9 E B D    x   [S] = [S*]
              D 9 E B
              B D 9 E]
        """
        two = BitVector(intVal=2, size=BYTE)
        three = BitVector(intVal=3, size=BYTE)
        E = BitVector(intVal=14, size=BYTE)
        D = BitVector(intVal=13, size=BYTE)
        B = BitVector(intVal=11,size=BYTE)
        nine = BitVector(intVal=9, size=BYTE)

        for j in range(len(S)):
            M[0][j] = S[0][j].gf_multiply_modular(two, MODULUS, 8) ^ S[1][j].gf_multiply_modular(three, MODULUS, 8) ^ S[2][j] ^ S[3][j]
            M[1][j] = S[0][j] ^ (S[1][j].gf_multiply_modular(two, MODULUS, 8)) ^ (S[2][j].gf_multiply_modular(three, MODULUS, 8)) ^ S[3][j]
            M[2][j] = S[0][j] ^ S[1][j] ^ (S[2][j].gf_multiply_modular(two, MODULUS, 8)) ^ (S[3][j].gf_multiply_modular(three, MODULUS, 8))
            M[3][j] = S[0][j].gf_multiply_modular(three, MODULUS, 8) ^ S[1][j] ^ S[2][j] ^ S[3][j].gf_multiply_modular(two, MODULUS, 8)

        return M

    def getLookupTable(self):
        return self.LTB

    def generate_lookup_table(self):
        self.LTB = [[(BitVector(size=4,intVal=r) + BitVector(size=4,intVal=c)) for c in range(self.LTB_SIZE)] for r in range(self.LTB_SIZE)]
        # replace with MI
        print "Generating LTB.."
        #affine
        for r in range(16):
            for c in range(16):
                if r == 0 and c == 0:
                    #there is no MI of 0
                    continue
                self.LTB[r][c] = self.LTB[r][c].gf_MI(MODULUS, 8)

        for r in range(16):
            for c in range(16):
                #bit scramble
                cbyte = BitVector(bitstring='01100011') #0x63
                for i in range(8):
                    print "b = ", self.LTB[r][c]
                    bi = self.LTB[r][c][i]
                    bi_4 = self.LTB[r][c][(i+4) % 8]
                    bi_5 = self.LTB[r][c][(i+5) % 8]
                    bi_6 = self.LTB[r][c][(i+6) % 8]
                    bi_7 = self.LTB[r][c][(i+7) % 8]
                    ci = cbyte[i]
                    self.LTB[r][c][i] = bi ^ bi_4 ^ bi_5 ^ bi_6 ^ bi_7 ^ ci

        print "------ LTB -------"
        for r in range(16):
            for c in range(16):
                print _hex(self.LTB[r][c]),
            print



class UnitTest:
    @staticmethod
    def test_round_constants(KeyScheduleObj):
        assert(len(KeyScheduleObj.Rcon) == 10)

    @staticmethod
    def test_round_keys(KeyScheduleObj):
        xkey = KeyScheduleObj.xkey
        assert(len(xkey) == 44)
        assert(xkey[40] + xkey[41] + xkey[42] + xkey[43] == KeyScheduleObj.get_key_for_round(10))
        for key in xkey:
            assert(len(key) == WORD)

    @staticmethod
    def test_shiftrow():
        M = [[None for r in range(4)] for c in range(4)]
        for i in range(4):
            for j in range(4):
                M[j][i] = BitVector(intVal=j,size=BYTE/2)+ BitVector(intVal=i, size=BYTE/2)

        Ms = AES.shiftrows(M)

        assert(Ms[0][0] == M[0][0])
        assert(Ms[0][1] == M[0][1])
        assert(Ms[0][2] == M[0][2])
        assert(Ms[0][3] == M[0][3])

        assert(Ms[1][0] == M[1][1])
        assert(Ms[1][1] == M[1][2])
        assert(Ms[1][2] == M[1][3])
        assert(Ms[1][3] == M[1][0])

        assert(Ms[2][0] == M[2][2])
        assert(Ms[2][1] == M[2][3])
        assert(Ms[2][2] == M[2][0])
        assert(Ms[2][3] == M[2][1])

        assert(Ms[3][0] == M[3][3])
        assert(Ms[3][1] == M[3][0])
        assert(Ms[3][2] == M[3][1])
        assert(Ms[3][3] == M[3][2])


if __name__ == "__main__":
    key = "lukeimyourfather"
    BLKSIZE = 128
    plain = BitVector(filename='plaintext.txt')

    crypt = AES(key)
    ksch = KeySchedule(key, BLKSIZE, crypt.getLookupTable())

    UnitTest.test_round_keys(ksch)
    UnitTest.test_round_constants(ksch)

    plain_t = plain.read_bits_from_file(BLKSIZE)
    output = crypt.encrypt(plain_t, ksch)
    print len(output), "bits cipher: ", _hex(output)