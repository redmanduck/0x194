#!/usr/bin/python
#
import hw07
import hashlib

en = open("document.txt", "r")
mesg = en.read()
en.close()

tests = [mesg,""]
results =[]

for strr in tests:
	m = hashlib.sha512()
	m.update(strr)
	result = hw07.hexdigest(strr)
	golden = m.hexdigest()
	if(result != golden):
		results.append("FAIL " + golden + " != " + result)
	else:
		results.append("PASS")

print results