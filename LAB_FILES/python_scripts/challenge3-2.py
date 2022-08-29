# import scapy
from scapy.all import *

# read the packet capture file
packets = rdpcap("/home/ubuntu/lab/LAB_FILES/exercise3.pcap")

# loop through each packet
for pkt in packets:
  if pkt.haslayer(DNS):
    # if a packet is DNS protocol
    if DNSQR in pkt:
      # print TXT data, ignore errors
      try:
        print(str(pkt.src)+":"+str(pkt[NDS].an.rdata))
      except:
        continue
