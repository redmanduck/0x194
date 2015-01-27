#!/usr/bin/python
#
### hw2_starter.py

import sys
from BitVector import *
import re

################################   Initial setup  ################################

# Expansion permutation (See Section 3.3.1):
expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 
9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 
20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

# P-Box permutation (the last step of the Feistel function in Figure 4):
p_box_permutation = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,
1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]

# Initial permutation of the key (See Section 3.3.6):
key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,
50,42,34,26,18,10,2,59,51,43,35,62,54,46,38,30,22,14,6,61,53,45,37,
29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3]

# Contraction permutation of the key (See Section 3.3.7):
key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,
7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,
33,52,45,41,49,35,28,31]

# Each integer here is the how much left-circular shift is applied
# to each half of the 56-bit key in each round (See Section 3.3.5):
shifts_key_halvs = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] 



###################################   S-boxes  ##################################

# Now create your s-boxes as an array of arrays by reading the contents
# of the file s-box-tables.txt:

s_box = []
try:
    arrays = []
    regex = re.compile("([0-9]+\s+)+")
    with open('s-box-tables.txt') as f:
        for line in f:
            result = regex.search(line)
            if result is not None:
                cand = result.group(0)
                lst = re.compile("\s+").split(cand)
                del lst[len(lst) -1]
                arrays.append(lst)
                for j,item in enumerate(lst):
                    lst[j] = int(lst[j])

    for i in range(0,32, 4):
       s_box.append([arrays[k] for k in range(i, i+4)]) # S_BOX

except Exception as ex:
    print ex
    raise Exception("Unable to read S-BOX. Is it in correct format ?")



#######################  Get encryptin key from user  ###########################

def get_encryption_key(): # key                                                              
    ## ask user for input and make sure it satisfies any constraints on the key
    user_supplied_key = ""
    while(len(user_supplied_key) != 8):
        user_supplied_key = raw_input("Please enter 8 character key: ")

    ## construct a bit vector (64 bit)
    user_key_bv = BitVector(textstring = user_supplied_key)
    
    # initial permutation 64 bit key
    key_bv = user_key_bv.permute( key_permutation_1 )        ## permute() is a BitVector function
    return key_bv


################################# Generatubg round keys  ########################

"""
    are round Key (Ki) for each round, i, different?
"""
def extract_round_key( nkey ): # round key
    print "Extracting Round Keys"
    roundkeys = []
    for i in range(16):
         [left, right] = nkey.divide_into_two()   ## divide_into_two() is a BitVector function
         left << shifts_key_halvs[i]
         right << shifts_key_halvs[i]
         rejoined_key_bv = left + right
         nkey = rejoined_key_bv  # the two halves go into next round
         roundkeys.append(rejoined_key_bv.permute(key_permutation_2))
         
    return roundkeys


########################## encryption and decryption #############################

def des(encrypt_or_decrypt, input_file, output_file, key ): 
    bv = BitVector( filename = input_file ) 
    FILEOUT = open( output_file, 'wb' ) 
    bv = BitVector( filename = input_file )

    bitvec = bv.read_bits_from_file( 64 )   ## assumes that your file has an integral
                                            ## multiple of 8 bytes. If not, you must pad it.
    [LE, RE] = bitvec.divide_into_two()      
    roundkeys = extract_round_key(key)

    for i in range(16):        
        ## write code to carry out 16 rounds of processing
        R_EStep48_L = e_step(RE)
        R_EStep48 = get_estep_output48(R_EStep48_L)
        rkey = BitVector(intVal = 55)
        mixed_key48 = R_EStep48 ^ rkey
        R_sub32 = substitution_step(s_box, mixed_key48)
        R_perm32 = permutation_step(p_box_permutation, R_sub32)

## Expansion Permutation
## returns 48 bits block
def e_step(RE32):
    print "Performing Expansion Permutation Step"
    if(RE32.size != 32):
        raise ValueError("Not a 32 bit value")
    words = []
    out = []
    # divide the 32 bit blocks into eight 4-bit words
    for i in range(8):
        start = 4*(i)
        end = start + 3
        words.append(RE32[start:(end + 1)])
        out.append(RE32[start:(end + 1)])
	
	# attach aditional bit on the LEFT of each word that is the last bit of the previous word
    for i,word in enumerate(words):
        if i-1 >= 0:
            #prepend with the last of previous word
            out[i] = BitVector(intVal= words[i-1][0]) +  word
        else:
            #prepend with the last of last word (overflow case) 
            out[i] = BitVector(intVal= words[len(words) - 1][3]) + word 


	# attach an additional bit to the RIGHT of each word that is the beginning of the next word
    for i,word in enumerate(out):
        if i+1 < len(out):
            #append with the beginning of next word
            out[i] = word + BitVector(intVal= words[i+1][0])
        else:
            #append with the beginning of first word (overflow case) 
            out[i] = word + BitVector(intVal= words[0][0])

    return out


## Substitution step enhance diffusion
def substitution_step(SBOX, XRE48):
    print "Performing Substitution Step"
    for i in range(len(SBOX)):
        print "Performing Substitution Step BOX ", i
        print XRE48
        row_index = BitVector(bitstring=(str(XRE48[6*i]) + str(XRE48[6*i + 5]))) #two outer bits
        col_index = XRE48[6*i + 1 : (6*i + 5)] #four inner bits
        print SBOX[i][row_index.int_val()][col_index.int_val()]
        fourbit_out = BitVector(size=4,intVal=SBOX[i][row_index.int_val()][col_index.int_val()])
        print str(fourbit_out)
    return None

def permutation_step(PBOX, XRE48):
	return XRE48


def get_estep_output48(padded_blocklist):
    bv = BitVector(size = 0)
    for block in padded_blocklist:
        bv = bv + BitVector(bitstring = str(block))
    if(bv.size != 48):
        raise ValueError("Output of estep is not 48 bit!")
    return bv

#################################### main #######################################

def test_estep():
    bv = BitVector(intVal = 2147483698)
    print str(bv)
    R = e_step(bv)

    for bit in R:
        print str(bit)

    xp48 = get_estep_output48(R)
    print xp48

def test_roundkey(uv):
    rk = extract_round_key(uv)
    for i,r in enumerate(rk):
        print "Round " + str(i), r , " size ", len(r)

def test_userkey():
    v = get_encryption_key()
    print "Your Key: " + str(v)
    return v


def main():
    ## write code that prompts the user for the key
    ## and then invokes the functionality of your implementation
    userkey = get_encryption_key()
    des(None, "peter.txt", "temp", userkey)

if __name__ == "__main__":
    main()
