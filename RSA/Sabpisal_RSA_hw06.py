#
#  RSA Duck
#
class RSADuck:
    def __init__(s, e=65537):
        s.e = e # condition is 1 < e < phi_n , gcd(phi_n ,e) = 1
        (s.p, s.q, s.n) = s.generate_pqn()
        s.d = s.compute_d()
        s.phi_n = (s.p - 1)*(s.q - 1) #phi_q * phi_p =  (p-1)*(q-1) for prime p, q

    def generate_pqn(self):
        return (53,59, 53*59)

    def compute_d(self):
        pass

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
