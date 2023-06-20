# import scapy
from scapy.all import *

# read the packet capture file
packets = rdpcap("/home/pslearner/lab/LAB_FILES/exercise3.pcap")

# loop through each packet
for pkt in packets:
  if pkt.haslayer(DNS):
    # if a packet is DNS protocol, print it
    print(pkt.show())
