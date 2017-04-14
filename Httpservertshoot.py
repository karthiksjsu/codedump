import logging 

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

icmp=ICMP()
ip=IP()

dstip=raw_input("Enter the IP Address of HTTP Server\n")

icmp.type=8
icmp.code=0
ip.dst=dstip

packet=ip/icmp
print "Pinging IP Address..."

reply=sr1(packet,timeout=4,verbose=0)

if(reply):
	if ((reply.code and reply.type)==0):
		print "IP address is live"
		tcp=TCP()
		tcp.dport=80
		tcp.flag='s'
		print "Initiating port scan"
		response=sr1(ip/tcp,timeout=4,verbose=0)
		if(response):
			if(response['TCP'].flags==18):
				print "The port is open"
			if(response['TCP'].flags==20):
				print "The port is closed or Unavailable"
		else:
			print "The port is closed or filtered"     
else:
	print "IP address is down"


