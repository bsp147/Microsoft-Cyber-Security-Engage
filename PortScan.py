# Port Scanner for scanning open ports and checking traffic

from scapy.all import *


def SynScan(host):
	for ports in range(1,65535):
		ans,unans = sr(IP(dst = host)/TCP(sport=5555,dport=ports,flags="S"),timeout=2,verbose=0)
		print("Open ports at %s:"%host)
		for(s,r,) in ans:
			if(s[TCP].dport == r[TCP].sport):
				print(s[TCP].dport)


def DNSScan(host):
	ans,uans = sr(IP(dst=host)/UDP(sport=5555,dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
	if ans:
		print("DNS Server at %s"%host)

host = "8.8.8.8"

SynScan(host)
DNSScan(host)