# PCAP Compare

This project is to create tools to compare two packet capture files in order to identify packet drops.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

```
python --version
Python 2.7.5
```

```
import dpkt
import json,re,argparse
import socket
```


### Example


```
python pcap-compare.py --help
usage: pcap-compare.py [-h] [--file FILE FILE]

Generate

optional arguments:
  -h, --help        show this help message and exit
  --file FILE FILE  inputfile
```



```
python pcap-compare.py --file test-ingress.pcap test-egress.pcap

##########################################################################################
Result for flow: TCP_10.137.84.68:58841-13.108.250.232:443
Total number of packets in test-ingress.pcap : 31
Packet drops: 22(test-ingress.pcap against test-egress.pcap)
Packet# 102
Packet# 126
Packet# 148
Packet# 149
Packet# 150
Packet# 151
Packet# 159
Packet# 161
Packet# 167
Packet# 168
Packet# 169
Packet# 170
Packet# 224
Packet# 293
Packet# 294
Packet# 295
Packet# 296
Packet# 331
Packet# 398
Packet# 399
Packet# 400
Packet# 401
Total number of packets in test-egress.pcap : 8
Packet drops: 0(test-egress.pcap against test-ingress.pcap)
##########################################################################################

```

