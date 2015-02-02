# Q1. with respect to which operation , modulo add, modulo multiply
#    does the set of remainders Z17 form a group?

def modadd(a,b,g):
	return (a + b) % g
def modmult(a,b,g):
	return (a+b) % g
def multinv(a,Z):
	n = len(Z)
	for i in Z:
		if (a * i) % n == 1:
			return i
	return -1
def addinv(a,Z):
	n = len(Z)
	for i in Z:
		if (a + i) % n == 1:
			return i
	return -1


Z17 = range(17)
# it is a group when a in Z17, b in Z17. a o b in Z17
for i in Z17:
	for j in Z17:
		A = modadd(i,j,17)
		B = modmult(i,j,17)
		if not A in Z17:
			print i, "+" ,j, " Not exist in Z17 (add op)"
		if not B in Z17:
			print i, "x", j , " Not exist in Z17 (mul op)"
	
	C = multinv(i, Z17)
	D = addinv(i, Z17)
	if C == -1:
		print "there is no multiplicative inv of ", i, j
	if D == -1:
		print "there is no additive inv of ", i ,j

## answer : modulo n addition will make Z17 a group

# Q2. List all steps involved in computing gcd(1056, 348)
# using i. euclid , ii. stein

# i. Euclid 
# gcd(tup)
# tup = (a,b)
def eugcd(tup):
	if(tup[0] == 0):
		return tup[1]
	elif(tup[1] == 0):
		return tup[0]

	tup_n = (tup[1], tup[0] % tup[1])
	print "euclid GCD", tup_n
	return eugcd(tup_n)

ans = eugcd((1056,348))
print "GCD(1056, 348) = ", ans

