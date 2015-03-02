#
#  256-RSA algorithm
#  Author: ssabpisa
#
from PrimeGenerator import PrimeGenerator
from BitVector import *
from Factorize import gcd
import json

class Key:
    e = 0
    n = 0
    d = 0
    def toFile(self, filename):
        f = open(filename, 'w')
        ob = {}
        if(self.e != 0):
            ob["e"] = self.e
        if(self.n != 0):
            ob["n"] = self.n
        if(self.d != 0):
            ob["d"] = self.d

        f.write(json.dumps(ob))
        f.close()

    def fromFile(self, filename):
        f = open(filename, 'r')
        ob = json.loads(f.read())
        for k in ob:
            if k == "e":
                self.e = ob[k]
            elif k == "n":
                self.n = ob[k]
            elif k == "d":
                self.d = ob[k]

        f.close()



class PublicKey(Key):
    def __init__(self,e,n):
        self.e = e;
        self.n = n;

class PrivateKey(Key):
    def __init__(self,d,n):
        self.d = d;
        self.n = n;

class RSADuck:
    def __init__(s, e=65537):
        s.e = e # public exponent is 1 < e < phi_n , gcd(phi_n ,e) = 1
        (s.p, s.q, s.n) = s.generate_pqn()
        s.phi_n = (s.p - 1)*(s.q - 1) #phi_q * phi_p =  (p-1)*(q-1) for prime p, q
        s.d = s.compute_d()  #private exponent

    def generate_pqn(self):
        G = PrimeGenerator(bits = 128, debug = False)
        p = G.findPrime()
        q = p
        while(not self.pqvalid(p,q)):
            q = G.findPrime()
            p = G.findPrime()
        n = p*q

        return (p,q,n)

    def pqvalid(s,p,q):
        p2 = bin(p)[2:][0:2]
        q2 = bin(q)[2:][0:2]
        cond1 = (p2 == q2) and (p2 == '11')
        cond2 = (p != q)
        cond3 = (gcd((p-1), s.e) == 1)  # (p-1) and (q-1) is coprime to e
        cond4 = (gcd(q-1, s.e) == 1)
        return cond1 and cond2 and cond3 and cond4

    #
    #  Compute private exponent
    #
    def compute_d(s):
        # d = e^-1 mod phi_n
        # aka d is multiplicative inverse of phi_n
        bv_phi = BitVector(intVal= s.phi_n)
        bv_e = BitVector(intVal = s.e)
        return int(bv_e.multiplicative_inverse(bv_phi))

    #
    #
    #  encrypt by calculating
    #  M^e mod n --> C
    #  key is PublicKey
    def encrypt_with_publickey(s, M_str, key):

        EC = [] #encrypted blocks
        nline = BitVector(textstring="\n")

        # read 16 character (128 bits) at a time
        Mbv = BitVector(textstring=M_str)
        for i in range(0, len(Mbv), 128):
            M_block = Mbv[i:i+128]

            while(len(M_block) < 128):
                M_block = M_block + nline;

            M_block.pad_from_left(128)

            C = pow(int(M_block), s.e, key.n)
            EC.append(BitVector(intVal=C, size=256))
            # each element in EC is 256 bits

        return EC


    #
    #  
    #  decrypt by
    #  k is Private Key
    #  C is message encrypted with public key
    #  C^k.d mod k.n, k.d is private exponent
    #
    def decrypt_with_privatekey(s, C_str, key, p, q):
        print "Decrypting.."
        # we need to know prime factor p, q of modulus n (n = p*q)
        # C^d is congruent to C mod n
        # unlocker must have key with d that is f(phi(n)), phi(n) is f(p,q), where
        # two prime factors of n are coprime to e
        # phi = (p-1)*(q-1)
        # n = p*q
        # d = MI(phi)

        DM = []
        # read 32 character (256 bits) at a time
        Cbv = BitVector(textstring=C_str)
        for i in range(0, len(Cbv), 256):
            C = int(Cbv[i:i+256])

            Vp = pow(C, key.d, p)
            Vq = pow(C, key.d, q)

            qbv = BitVector(intVal=q)
            pbv = BitVector(intVal=p)


            Xp = int(qbv.multiplicative_inverse(pbv))*int(qbv)
            Xq = int(pbv.multiplicative_inverse(qbv))*int(pbv)
            C_raise_d = (Vp*Xp + Vq*Xq) % key.n 
            DM.append(BitVector(intVal=C_raise_d, size=128))

        return DM

    def get_keys(s):
        return (PrivateKey(s.d, s.n), PublicKey(s.e, s.n))

    def getPQ(self):
        return {"p": self.p, "q": self.q}



def jsonwrite(js, filename):
    f = open(filename, "w")
    f.write(json.dumps(js))
    f.close()

def jsonread( filename):
    f = open(filename, "r")
    L = f.read()
    f.close()
    return json.loads(L)
#
# block is is list of bitvector
#
def fwrite(blocklist, filename):
    strbuf = ""
    f = open(filename, "w")
    for block in blocklist:
        tmp = block.get_text_from_bitvector()
        f.write(tmp)
        strbuf = strbuf + tmp
    f.close()

    return strbuf

if __name__ == "__main__":

    if(len(sys.argv) < 4):
        print "Usage: Sabpisal_RSA_hw06.py -[mode] -[src] -[dest]"
        print "mode: e for encrypt, d for decrypt"
        sys.exit(1)

    R = RSADuck()

    try:
        msg = open(sys.argv[2] , "r")
    except IOError:
            print "Unable to open file", sys.argv[2]
            sys.exit(1)

    if(sys.argv[1] == "-e"):
        private, public = R.get_keys()
        PQPair = R.getPQ()

        private.toFile("private.json")
        public.toFile("public.json")
        jsonwrite(PQPair, "pq.json")

        eblob = R.encrypt_with_publickey(msg.read(), public)
        enctxt = fwrite(eblob, sys.argv[3])

    elif(sys.argv[1] == "-d"):
        private = PrivateKey(0,0)
        try:
            private.fromFile("private.json")
            PQPair = jsonread("pq.json")
        except IOError:
            print "Make sure you have private.json and pq.json"
            sys.exit(1)
        dblob = R.decrypt_with_privatekey(msg.read(), private, PQPair['p'], PQPair['q'])
        dectxt = fwrite(dblob, sys.argv[3])
        print dectxt

    msg.close()

