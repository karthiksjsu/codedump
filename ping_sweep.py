import logging


logging.basicConfig(filename="example.log",level=logging.DEBUG)
logger=logging.getLogger("scapy.runtime")
logger.disabled=True


from scapy.all import *

#logging.info(" create the packet based on your network ")

ip=IP(ttl=20)
icmp=ICMP()
icmp.type=8
icmp.code=0

print "Starting Ping Sweep......."

for i in range (0,255):
	ip.dst="10.0.2."+str(i)
	packet=ip/icmp
	reply=sr1(packet,timeout=5,verbose=0)
	if(reply):
        	if reply.type is 0 and reply.code is 0 and reply.src == ip.dst:
               		print reply.src ,"is online" 
                        logging.info('%s is online',reply.src)
        	else:
			print "Timeout waiting for %s" % packet[IP].dst
			
	else:
		print "Timeout waiting for %s" % packet[IP].dst
		

