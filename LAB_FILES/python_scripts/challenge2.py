# import scapy and libraries
from scapy.all import *
from scapy.layers import http
from collections import Counter

# read the packet capture file
packets = rdpcap("/home/ubuntu/lab/LAB_FILES/exercise2.pcapng")

# two empty lists to store host and UA strings
HT = []
UA = []

# loop through each packet
for pkt in packets:
  if pkt.haslayer(http.HTTPRequest):
    # only read packets containing http
    http_layer = pkt.getlayer(http.HTTPRequest)
    try:
      # add host and UA string, to lists
      HT.append(http_layer.fields['Host'].decode('utf-8))
      UA.append(http_layer.fields['User_Agent'].decode('utf-8'))
    except Exception as e:
      continue

# count the results from each list
Hosts = Counter(HT)
UserAgentStrings = Counter(UA)

# using the counted lists, displat the most common hosts and least common UA strings
print("Most Common Hosts: ", Hosts.most_common(10))
print("Least Common User Agent Strings: ", UserAgentStrings.most_common(5)[-1])

