import sys
from BitVector import BitVector

# Multiplicative Inverse
def multinv(a,Z):
	n = len(Z)
	for i in Z:
		if (a * i) % n == 1:
			return i
	return -1

# Additive Inverse
def addinv(a,Z):
	n = len(Z)
	for i in Z:
		if (a + i) % n == 1:
			return i
	return -1

# GCD
def eugcd(tup):

	if(tup[0] == 0):
		return tup[1]
	elif(tup[1] == 0):
		return tup[0]
	elif(tup[1] == tup[0]):
		return tup[1]

	tup_n = (tup[1], tup[0] % tup[1])
	return eugcd(tup_n)

def modadd(a,b,g):
	return (a + b) % g

def modmult(a,b,g):
	return (a+b) % g

def isRing(R, n):
	return True


def isCommutativeRing(R, n):
	# ab = ba for all a , b in R
	# for multiplication operator
	return True

def isIntegralDomain(R, n):
	# is commutative ring
	# + R has identity for Mult op -- a1 = 1a = a
	# + for any a,b in R -> ab = 0 , a = 0 or b = 0
	return True

def isField(R, n):
	# is Ring
	# is Integral Domain
	# for every element a in F (a != 0)
	# MI(a) is in F

	if not isRing(R, n):
		return False
	if not isIntegralDomain(R, n):
		return False
	for a in R:
		if(a == 0):
			continue
		gcd = eugcd((a, n))
		if gcd != 1:
			#there is an entry in R where there si no MI
			return False

	return True


n = input('For Zn, Enter n (n < 50): ')
Zn = range(n) 
print "Z" + str(n) +  " is Field: ", isField(Zn, n)
#if its not a field is it a ring??