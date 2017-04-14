import logging

logging.getLogger("scapy runtime").setLevel(logging.ERROR)

from scapy.all import *
dstip=raw_input("Enter the IP for which the status needs to be checked\n")

logging.info("constructing ARP message")

arp=ARP()
arp.hwdst='00:00:00:00:00:00'
arp.hwsrc='08:00:27:dd:f5:3a'
arp.pdst=dstip
arp.src='10.0.2.15'
 
ether=Ether()
ether.dst='FF:FF:FF:FF:FF:FF'
ether.src='08:00:27:dd:f5:3a'

packet=ether/arp

reply=srp1(packet,timeout=5,verbose=0)

if(reply):
	print "Layer2 status is up and at " +reply.src
        #print reply.show()
else:
	print "Layer2 status is down"
        logging.warning(" Status is down")


