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
		print "there is no multiplicative inv of ", i
	if D == -1:
		print "there is no additive inv of ", i

## answer : modulo n addition will make Z17 a group

# Q2. List all steps involved in computing gcd(1056, 348)
# using i. euclid , ii. stein

# i. Euclid 
# gcd(tup)
# tup = (a,b)
def eugcd(tup):
	print "euclid GCD", tup

	if(tup[0] == 0):
		return tup[1]
	elif(tup[1] == 0):
		return tup[0]
	elif(tup[1] == tup[0]):
		return tup[1]

	tup_n = (tup[1], tup[0] % tup[1])
	return eugcd(tup_n)

def steingcd(tup):
	print "stein GCD", tup

	tup0_even = (tup[0] & 0x1 == 0)
	tup1_even = (tup[1] & 0x1 == 0) 

	if(tup[0] == 0):
		return tup[1]
	if(tup[1] == 0):
		return tup[0]
	if(tup[1] == tup[0]):
		return tup[1]

	if(tup0_even and tup1_even):
		return steingcd((tup[0] >> 1, tup[1] >> 1)) << 1;

	if (tup0_even and not tup1_even):
		return steingcd((tup[0] >> 1, tup[1]))

	if (tup0_even):
		return steingcd(tup[0], tup[1] >> 1)

	if (tup[0] > tup[1]):
		return steingcd(( (tup[0] - tup[1]) >> 1, tup[1]  ))

	return steingcd((tup[0], (tup[1] - tup[0]) >> 1));


ans = eugcd((1056,348))
print "eGCD(1056, 348) = ", ans
print "=============================="
ans = steingcd((1056,348))
print "sGCD(1056, 348) = ", ans
# stein GCD (1056, 348)
# stein GCD (528, 174)
# stein GCD (264, 87)
# stein GCD (132, 87)
# stein GCD (66, 87)
# stein GCD (33, 87)
# stein GCD (33, 27)
# stein GCD (3, 27)
# stein GCD (3, 12)
# stein GCD (3, 4)
# stein GCD (3, 0)
# sGCD(1056, 348) =  12
print "=============================="


# Q3. Use Extended Euclid Algorithm to compute by hand the
# multiplicative inverse of 21 in Z34. List all steps

# ax + by = gcd(a,b)
# on paper

# Q4. Which non zero eleme in Z14 has no MI

Z14 = range(14)
nmi = []
for a in Z14:
	ans = eugcd((a,14))
	if(ans != 1):
		nmi.append(a)

print nmi

