# NS1 (Network Security 1)

Homework 3
----
Find all TCP packets in a given pcap file and for each packet output:
source MAC, destination MAC, ethernet type, source IP, destination IP, IP protocol, TCP source port, TCP destination port, type of scanning (Null or Xmas)
  - Null scan packet - Does not have any flags set (TCP flag header is 0)
  - Xmas scan packet - Has only the FIN, PSH, and URG flags set
