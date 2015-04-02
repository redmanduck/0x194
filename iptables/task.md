**Homework 9** - Suppatach Sabpisal	

From perspective of `ecegrid.cloudapp.net`

### 1. Block all incoming connections from `maven.itap.purdue.edu`

    sudo iptables -A INPUT -s 128.210.209.15 -j DROP

**Test**:

    ssh maven.itap.purdue.edu
    > ping ecegrid.cloudapp.net

### 2. Block all ICMP packet from ANY host

    iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT

**Test**:

    ssh condux.cloudapp.net
    > ping ecegrid.cloudapp.net
    ssh ecegrid.ecn.purdue.edu
    > ping ecegrid.cloudapp.net
    ssh ecegrid.cloudapp.net
    > ping ecegrid.cloudapp.net

### 3. Setup port forwarding from PORT 9000 to 22.

    sudo iptables -t nat -A PREROUTING -p tcp --dport 9000 -j REDIRECT --to-port 22
	sudo iptables -A INPUT -p tcp --dport 9000 -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p tcp --sport 9000 -m state --state ESTABLISHED -j ACCEPT

**Test**:

    ssh -p 9000 ecegrid.cloudapp.net

### 4. Block 22 except from `ecn.purdue.edu` domain

    sudo iptables -A INPUT -p tcp -s 128.46.4.0/24 --dport ssh -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport ssh -j DROP

**Test**:

    ssh condux.cloudapp.net    #[1]
    > ssh ecegrid.cloudapp.net
    ssh ecegrid.ecn.purdue.edu #[2]
    > ssh ecegrid.cloudapp.net
    ssh shay.ecn.purdue.edu    #[3]
    > ssh ecegrid.cloudapp.net
    
**Result**: Only [2], [3] succeed. [1] failed.

### 5. Allow one IP only, to be able to access this HTTPD server.

    sudo iptables -A INPUT -p tcp -s ecegrid-thin1.ecn.purdue.edu --dport 80 -j ACCEPT
    sudo iptables -A INPUT -p tcp -s ecegrid-thin1.ecn.purdue.edu --dport 443 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 80 -j DROP
    sudo iptables -A INPUT -p tcp --dport 8443 -j DROP    

**Test**:

    ssh ecegrid.ecn.purdue.edu
    > curl ecegrid.cloudapp.net
    

### 6. Permit Auth/Ident (113) used by IRC or SMTP

	iptables -A INPUT -p tcp -m tcp --dport 113 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport -j DROP