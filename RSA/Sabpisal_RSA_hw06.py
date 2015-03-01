#
#  RSA Duck
#
from PrimeGenerator import PrimeGenerator
from BitVector import *
from Factorize import gcd

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
        n = p*q

        return (p,q,n)

    def pqvalid(s,p,q):
        p2 = bin(p)[2:][0:2]
        q2 = bin(q)[2:][0:2]
        cond1 = (p2 == q2) and (p2 == '11')
        cond2 = (p == q)
        cond3 = (gcd((p-1), s.e) == 1)  # (p-1) and (q-1) is coprime to e
        cond4 = (gcd(q-1, s.e) == 1)
        return cond1 and cond2 and cond3 and cond4

    def compute_d(s):
        # d = e^-1 mod phi_n
        # aka d is multiplicative inverse of phi_n
        bv_phi = BitVector(intVal= s.phi_n)
        bv_e = BitVector(intVal = s.e)
        return int(bv_e.multiplicative_inverse(bv_phi))


    def D():
        pass

    def E():
        pass

    def encrypt(self, M, PRa, PUb):
        pass

    def decrypt(self, C, PRb, PUa):
        pass

    def get_public_key(s):
        return [s.e, s.n]

    def get_private_key(s):
        return [s.d, s.n]

    @staticmethod
    def modular_exponentiate(a,x):
        # use CRT
        pass


if __name__ == "__main__":
    duck = RSADuck()
