#!/bin/bash
#
# Block all incoming connections from `maven.itap.purdue.edu`
iptables -A INPUT -s 128.210.209.15 -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT
# Block all ICMP packet from ANY host
iptables -t nat -A PREROUTING -p tcp --dport 9000 -j REDIRECT --to-port 22
# Setup port forwarding from PORT 9000 to 22.
iptables -A INPUT -p tcp --dport 9000 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 9000 -m state --state ESTABLISHED -j ACCEPT
# Block 22 except from `ecn.purdue.edu` domain
iptables -A INPUT -p tcp -s 128.46.4.0/24 --dport ssh -j ACCEPT
iptables -A INPUT -p tcp --dport ssh -j DROP
# Allow one IP only, to be able to access this HTTPD server.
iptables -A INPUT -p tcp -s ecegrid-thin1.ecn.purdue.edu --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -s ecegrid-thin1.ecn.purdue.edu --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 8443 -j DROP
# Permit Auth/Ident (113) used by IRC or SMTP
iptables -A INPUT -p tcp -m tcp --dport 113 -j ACCEPT
iptables -A INPUT -p tcp --dport -j DROP