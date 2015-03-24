import sys
from socket import *

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        fj = open("openports.txt", "w")

        for port in range(rangeStart, rangeEnd):
            print "Scanning port %5d" % port,
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.1) # wait 10 seconds
            try:
                s.connect((self.targetIP, port))
                print "[OPEN]"
                fj.write(str(port))
            except Exception:
                print
            finally:
                s.close()

        fj.close()

    def attackTarget(self, port):
        pass


# captive_dns_addr = gethostbyname("iprint1.ics.illinois.edu")
Tcp = TcpAttack('128.210.7.199', '128.210.7.199')
Tcp.scanTarget(70, 100)