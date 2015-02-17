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
from base64 import b64encode
import utest as test

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
    if len(ib) != BYTE:
        raise Exception("Input BYTE to find sub is not a byte")
    r = int(ib[0:4])
    c = int(ib[4:8])
    # print "look up " ,r,c
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
        for c in range(self.state_dim):
            for r in range(self.state_dim):
                self.statearray[r][c] = BitVector(bitstring=self.keybv[WORD*c + BYTE*r : WORD*c + BYTE*(r+1)])

        print "--------- Input Key Matrix (K) ----------"
        for r in range(self.state_dim):
            for c in range(self.state_dim):
                print _hex(self.statearray[r][c]), " | ",
            print

        #the first four w0...w3
        for c in range(4):
            wn = BitVector(size=0)
            for r in range(4):
                wn += self.statearray[r][c]
            self.xkey.append(wn)


        for key in self.xkey:
            print _hex(key)


        # expand {w0...w3} -> {w0...w43} for the 10 rounds
        for i in range(10):
            self.expand(i)

        # print "----------- Expanded Key (W): 44 Words ----------------"
        # for i, wrd in enumerate(self.xkey):
        #     print 'w'+str(i), "=",
        #     print _hex(wrd), ",",
        # print

    def g(self, k, rnd):
        print "g(", _hex(k), ")",
        w = deepcopy(k)
        #check if w is 4 byte
        if(len(w) != 4*BYTE):
            raise Exception("g(word), word is not 4 byte!")
        #perform 1 byte left circular shift
        w << BYTE
        print "after rot = ", _hex(w),
        #perform a byte substitution for each byte of the word
        wf = BitVector(size=0)

        wf += _getSubstitute(w[0:8], self.LTB)
        wf += _getSubstitute(w[8:16], self.LTB)
        wf += _getSubstitute(w[16:16+8], self.LTB)
        wf += _getSubstitute(w[16+8:32], self.LTB)

        print "after sub = ", _hex(wf),

        #XOR bytes with round const
        usercon = self.Rcon[rnd]
        print "rcon i = ", _hex(usercon),
        wx = usercon ^ wf

        print "after $rcon", _hex(wx),

        return wx

    def generate_RC(self):
        RC = [BitVector(intVal=1, size=BYTE)]*10
        for j in range(1, 10):
            RC[j] =  RC[j-1].gf_multiply_modular(BitVector(intVal=2), MODULUS, 8)

        EMPTYBYTE = BitVector(size=BYTE)
        self.Rcon.append(RC[0] + EMPTYBYTE + EMPTYBYTE + EMPTYBYTE)
        for i in range(1,10):
            self.Rcon.append(RC[i] + EMPTYBYTE + EMPTYBYTE + EMPTYBYTE)

    """
        generate the next set of N words

        ['6c756b65', '696d796f', '75726661', '68657274', 'bd382bf7', 'd4555298', 'a12734f9', '42468dc9', '9362bc8f', '4737ee17', 'e610daee', '565727a4', '263970c6', '610e9ed1', '871e443f', '49639bd1', 'adc2acf8', 'cccc3229', '4bd27616', 'b1edc702', '751b6a8f', 'b9d758a6', 'f2052eb0', 'e8e9b243', 'b4e35d95', '0d340533', 'ff312b83', 'd899c017', '8462e765', '8956e256', '7667c9d5', 'fe09c2ae', '461ec241', 'cf482017', 'b92fe9c2', '262b6c47', 'aa3881e1', '6570a1f6', 'dc5f4834', '742473fa', '0e0e0e68', '6b7eaf9e', 'b721e7aa', 'c3059450']

        ['6c756b65', '696d796f', '75726661', '68657274', 'bd382bf7', 'd4555298', 'a12734f9', '42468dc9', '9362bc8f', '4737ee17', 'e610daee', '565727a4', '263970c6', '610e9ed1', '871e443f', '49639bd1', 'adc2acf8', 'cccc3229', '4bd27616', 'b1edc702', '751b6a8f', 'b9d758a6', 'f2052eb0', 'e8e9b243', 'b4e35d95', '0d340533', 'ff312b83', 'd899c017', '8462e765', '8956e256', '7667c9d5', 'fe09c2ae', '461ec241', 'cf482017', 'b92fe9c2', '262b6c47', 'aa3881e1', '6570a1f6', 'dc5f4834', '742473fa', '0e0e0e68', '6b7eaf9e', 'b721e7aa', 'c3059450']



    """
    def expand(self, offset):
        N = self.state_dim
        rnd = offset #round number

        i = len(self.xkey)
        # self.xkey[0][i] gives i-th byte of w0
        tmp = self.g(self.xkey[i -1], rnd)
        wink = self.xkey[i-4]
        print " tmp ", _hex(tmp),
        print " W[i-nk]", _hex(wink),

        w0 = tmp ^ wink
        print " w[i] = ", _hex(w0)
        # print "w" + str(len(self.xkey)) + " = " + "g(w%d) ^ w%d" % (offset*N + (N - 1), offset*N)
        self.xkey.append(w0)

        for i in range(1,N):
            x = len(self.xkey)
            tmp = self.xkey[x - 1]
            wink = self.xkey[x - 4]
            print "tmp = ", _hex(tmp),
            print "wnk = ", _hex(wink),
            wi = tmp ^ wink
            print "W[i] = " , _hex(wi)
            # print "w" + str(len(self.xkey)) + " = " + "w%d ^ w%d" % (len(self.xkey) - 1, i + offset*N)
            self.xkey.append(wi)

    def get_key_for_round(self, i):
        # print "Using encryption key w%d - w%d" % (i*4, i*4+3)
        return self.xkey[i*4] + self.xkey[i*4+1] + self.xkey[i*4+2]  + self.xkey[i*4+3]

    def get_key_for_round_decrypt(self, i):
        # print "Using decryption key w%d - w%d" % (40 - 4*i, 40 - 4*i + 3)
        return self.xkey[40 - 4*i] + self.xkey[40 - 4*i + 1] + self.xkey[40 - 4*i + 2]  + self.xkey[40 - 4*i + 3]

class AES:
    LTB = []# look up table
    LTB_SIZE = 16

    DLTB = [] # decrypt ltb


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
        inputt = self.state_array_from_bv128(textbv)
        print "> INPUT : "
        print_state(inputt)
        print " round key ", _hex(keyschedule.get_key_for_round(0))
        textbv = AES.add_round_key(textbv , keyschedule.get_key_for_round(0))
        state_r = self.state_array_from_bv128(textbv)
        print "> Added with RK: "
        print_state(state_r)


        for i in range(10):
            print "Encryption Round ", i+1
            raw_input("Enter to continue..")
            state_r = self.round_process(state_r, keyschedule.get_key_for_round(i+1), i==9)

        return self.reconstruct_column_wise(state_r)

    def decrypt(self, textbv, keyschedule):
        textbv = AES.add_round_key(textbv , keyschedule.get_key_for_round_decrypt(0))
        state_r = self.state_array_from_bv128(textbv)
        for i in range(10):
            # print "Decryption Round ", i+1
            state_r = self.round_process(state_r, keyschedule.get_key_for_round_decrypt(i+1), i==9)

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
            print bv
            print roundkey_bv
            raise Exception("Round Key and BV len not equal!")
        return roundkey_bv ^ bv

    def round_process(self, state_r, roundkey_bv, IS_LAST):
        if(state_r == None):
            raise Exception("State Array is None")
        print "Start of Round State: "
        print_state(state_r)
        raw_input("Enter to continue..")

        # keybytes = []
        # for i in range(16):
        #     keybytes.append(roundkey_bv[i*8:i*8+8])

        if(self.mode == AES.ENCRYPT):
            # SUB BYTE
            state_r = AES.subbyte(self.getLookupTable(), state_r)
            print "After SubByte: "
            print_state(state_r)
            raw_input("Enter to continue..")
            # SHIFT ROW
            state_r = AES.shiftrows(state_r)
            print "After Shiftrow: "
            print_state(state_r)
            raw_input("Enter to continue..")
            # MIX COLUMN
            if not IS_LAST:
                print "IS NOT LAST ENC"
                state_r = AES.mixcolumns(state_r)
            else:
                print "IS LAST ENC"

            print "After MixColumn (or not): "
            print_state(state_r)
            raw_input("Enter to continue..")

            # add round KEY
            # g=0
            # for c in range(len(state_r)):
            #     for r in range(len(state_r)):
            #         xorkey = keybytes[g]
            #         state_r[r][c] = AES.add_round_key(state_r[r][c], xorkey)
            #         g = g +1

            print "Round Key", _hex(roundkey_bv)

            temp = self.reconstruct_column_wise(state_r)
            XK = AES.add_round_key(temp, roundkey_bv)
            state_r = self.state_array_from_bv128(XK)

            print "After Added with RK :"
            print_state(state_r)
            raw_input("Enter to continue..")

        else:
            # INV SHIFT ROW
            state_r = AES.inverse_shiftrows(state_r)
            # INV SUB
            state_r = AES.subbyte(self.getLookupTable(), state_r)
            # ADD RND K

            # g=0
            # for c in range(len(state_r)):
            #     for r in range(len(state_r)):
            #         xorkey = keybytes[g]
            #         state_r[r][c] = AES.add_round_key(state_r[r][c], xorkey)
            #         g = g +1

            temp = self.reconstruct_column_wise(state_r)
            XK = AES.add_round_key(temp, roundkey_bv)
            state_r = self.state_array_from_bv128(XK)

            # INV MIX COLUMN
            if not IS_LAST:
                print "IS NOT LAST DEC"
                tate_r = AES.inverse_mixcolumns(state_r)
            else:
                print "IS LAST DEC"

        return state_r

    @staticmethod
    def inverse_shiftrows(M):

        # print "--------- Inv Shift Row ----------"
        N = len(M)
        MF = deepcopy(M)
        M0 = deepcopy(M)

        for r in range(1,N):
            for c in range(N):
                cx = c - r
                if(cx < 0):
                    #wrap around
                    over = 0 - cx
                    cx = N - over

                # print "(%d, %d) -> (%d, %d)" % (r,c, r, cx)
                MF[r][c] = M0[r][cx]

        return MF


    @staticmethod
    def shiftrows(M):
        # print "--------- Shift Row ----------"
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

                # print "(%d, %d) -> (%d, %d)" % (r,c, r, cx)
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
    def inverse_mixcolumns(S):
        M =  [[0 for x in range(4)] for x in range(4)]

        """

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
            M[0][j] = S[0][j].gf_multiply_modular(E, MODULUS, 8) ^ S[1][j].gf_multiply_modular(B, MODULUS, 8) ^ S[2][j].gf_multiply_modular(D, MODULUS, 8) ^ S[3][j].gf_multiply_modular(nine, MODULUS, 8)
            M[1][j] = S[0][j].gf_multiply_modular(nine, MODULUS, 8) ^ (S[1][j].gf_multiply_modular(E, MODULUS, 8)) ^ (S[2][j].gf_multiply_modular(B, MODULUS, 8)) ^ S[3][j].gf_multiply_modular(D, MODULUS, 8)
            M[2][j] = S[0][j].gf_multiply_modular(D, MODULUS, 8) ^ S[1][j].gf_multiply_modular(nine, MODULUS, 8) ^ (S[2][j].gf_multiply_modular(E, MODULUS, 8)) ^ (S[3][j].gf_multiply_modular(B, MODULUS, 8))
            M[3][j] = S[0][j].gf_multiply_modular(B, MODULUS, 8) ^ S[1][j].gf_multiply_modular(D, MODULUS, 8) ^ S[2][j].gf_multiply_modular(nine, MODULUS, 8) ^ S[3][j].gf_multiply_modular(E, MODULUS, 8)

        return M

    @staticmethod
    def mixcolumns(S):

        M =  [[0 for x in range(4)] for x in range(4)]

        """
            Encryption

            [ 2 3 1 1
              1 2 3 1    x   [S] = [S*]
              1 1 2 3
              3 1 1 2 ]


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

        if(self.mode == self.ENCRYPT):
           return self.LTB
        return self.DLTB


    def generate_lookup_table(self):
        self.LTB = [[(BitVector(size=4,intVal=r) + BitVector(size=4,intVal=c)) for c in range(self.LTB_SIZE)] for r in range(self.LTB_SIZE)]
        self.DLTB = [[(BitVector(size=4,intVal=r) + BitVector(size=4,intVal=c)) for c in range(self.LTB_SIZE)] for r in range(self.LTB_SIZE)]

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
                dbyte = BitVector(bitstring='00000101')
                #for i in range(8):
                #    self.LTB[r][c][i] = LRC[i] ^ LRC[(i+4) % 8] ^ LRC[(i+5) % 8] ^ LRC[(i+6) % 8] ^ LRC[(i+7) % 8] ^ cbyte[i]
                a1,a2,a3,a4 = [self.LTB[r][c].deep_copy() for x in range(4)]
                self.LTB[r][c] ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ cbyte
                b1,b2,b3 = [self.DLTB[r][c].deep_copy() for x in range(3)]
                b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ dbyte
                check = b.gf_MI(MODULUS, 8)
                b = check if isinstance(check, BitVector) else BitVector(intVal=0,size=BYTE)
                self.DLTB[r][c] = b

        print "------ ENC SBOX -------"
        for r in range(16):
            for c in range(16):
                print self.LTB[r][c].intValue(),
            print


        print "------ DEC SBOX -------"
        for r in range(16):
            for c in range(16):
                print self.DLTB[r][c].intValue(),
            print


if __name__ == "__main__":
    key = BitVector(hexstring='2b7e151628aed2a6abf7158809cf4f3c').get_text_from_bitvector()
    BLKSIZE = 128
    plain = BitVector(filename='plaintext.txt')
    cipherf = open('encryptedtext.txt', 'wb')
    plainf = open('decryptedtext.txt', 'w')


    mockplaintext = BitVector(hexstring='3243f6a8885a308d313198a2e0370734')
    print len(mockplaintext) , "bits data"
    crypt = AES(key)
    LTB = crypt.getLookupTable()           # LTB is correct
    ksch = KeySchedule(key, BLKSIZE, LTB)  #Key schedule is correct

    for rc in ksch.Rcon:
        print _hex(rc)

    enctxt = ""
    # for x in range(20):
    plain_t = mockplaintext
    output = crypt.encrypt(plain_t, ksch)
    enctxt += _hex(output)
    output.write_to_file(cipherf);

    print enctxt

    cipherf.close()

    ###### Decryption test #########
    # dec = AES(key, BLKSIZE, AES.DECRYPT)
    # cipher = BitVector(filename='encryptedtext.txt')
    # bufft = ""
    # for x in range(20):
    #     cipher_t = cipher.read_bits_from_file(BLKSIZE)
    #     output = dec.decrypt(cipher_t, ksch)
    #     bufft += output.get_text_from_bitvector()
    #     output.write_to_file(plainf);

    # print bufft
    # plainf.close()


    # ###### Tests ######

    test.UnitTest.test_round_keys(ksch)
    # test.UnitTest.test_round_constants(ksch)
    # test.UnitTest.test_esbox(LTB)
