# import the scapy library
from scapy.all import *

# read the packet capture file
packets = rdpcap("/home/pslearner/lab/LAB_FILES/exercise1.pcapng")

# loop through each packet
for pkt in packets:
  if IP in pkt:
    # print source and destination ip addresses and ports
    print(str(pkt[IP].src)+"-->"+str(pkt[IP].dst)+" : "+str(pkt[IP].dport)+"-->"+str(pkt[IP].sport))

