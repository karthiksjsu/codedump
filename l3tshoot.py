import logging

logging.getLogger("scapy runtime").setLevel(logging.ERROR)

from scapy.all import *

dstip=raw_input("Enter the IP for which the status needs to be checked\n")

icmp=ICMP()
icmp.type=8
icmp.code=0

ip=IP()
ip.dst=dstip

packet=ip/icmp

reply=sr1(packet,timeout=5,verbose=0)


if(reply):
        if reply.type is 0 and reply.code is 0 and reply.src == dstip:
               	print "Layer3 status is up"
        else:
		print "Layer3 status is down"
		logging.warning("Status is down")
else:
	print "Layer3 status is down"
	logging.warning("Status is down")



