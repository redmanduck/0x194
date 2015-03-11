#
#  Testing Miller-Rabin Test
#  author: ssabpisa
#
#
import sys
def find_kq(p):
    # find some positive k and odd q that makes
    # p - 1 = 2^k * q
    # (p-1)/q = 2^k
    # dlog_2_( [p-1]/q  ) = k
    # ask how many times does 2 have to repeat until it get to (p-1)/q
    k = 0
    q = p-1
    while not q&1:
        q >>= 1    # divide by 2 until not integer
        k += 1
    return k,q

n  = 389
prime = False
probes = [2,3,5,7,11,13,17]
#compute a^m == +/- 1 mod n
for a in probes:
    k,q = find_kq(n)
    a_q = pow(a, q, n)
    #condition
    if(a_q == 1):
        prime = True
        continue

    exp = 2*q
    while(exp < k-1):
        #check for congruence with -1 mod p
        #ie. p - 1
        a_qf = pow(a, exp, n)
        if(a_qf == p-1):
            prime = True
            continue
        exp = exp*2


if not prime:
    print n, "is not prime"
else:
    print n, "is prime with probability ", 1 - (1.0/pow(4, len(probes)))