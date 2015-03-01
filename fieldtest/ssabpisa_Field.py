## Suppatach Sabpisal
## ssabpisa@purdue.edu
import sys
from BitVector import BitVector

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

def isField(R, n):
	for a in R:
		if(a == 0):
			continue
		gcd = eugcd((a, n))
		if gcd != 1:
			#there is an entry in R where there si no MI
			return False
	return True


fout = open("output.txt","w")
n = input('For Zn, Enter n (n < 50): ')
Zn = range(n) 
if(isField(Zn, n)):
	fout.write("field")
else:
	fout.write("ring")

fout.close()