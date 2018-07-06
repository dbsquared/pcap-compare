import dpkt
import json,re,argparse
import socket

def dpktIpToString(dpktIP):
    ipAddrStr = socket.inet_ntoa(dpktIP)
    return ipAddrStr

def isKeyExistInList(key, list):
    for dict in list:
        if key in dict: return false
    return true


def pcapToList(filename):   #input: pcap file name, output: list of dictionaries, {pktNo, ts, pkt}
    pktList = []
    pktNo = 1
    for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
        pktDict = {}
        pktDict['ts'] = ts
        pktDict['pkt'] = pkt
        pktDict['pktNo'] = pktNo
        pktList.append(pktDict)
        pktNo = pktNo + 1

    return pktList
    '''
    pktList = [
                { 'pktNo': 0, 'ts': 1528331954.69, 'pkt': <the packet buffer> },
                { 'pktNo': 1, 'ts': 1528331955.69, 'pkt': <the packet buffer> },
                .....
              ]
    '''

def l4flowPicker(pktList): #input: pktList;
                           #output: list of dictionaries, {'l4flow': 'TCP_src_ip:sp-dst_ip:dp',
                           #                                'pkts': [ <elemtn from pktList>,
                           #                                           ......
                           #                                         ]
                           #                               }

    l4flowList = []
    for pkt in pktList:
        eth = dpkt.ethernet.Ethernet(pkt['pkt'])
        ip = eth.data
        l4 = ip.data

        srcIP = ""
        dstIP = ""
        proto = ""
        sPort = ""
        dPort = ""
        #print "pkt#: " + str(pkt['pktNo'])
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            srcIP = dpktIpToString(ip.src)
            dstIP = dpktIpToString(ip.dst)
        else:
            #only support IPv4
            continue

        if ip.p==dpkt.ip.IP_PROTO_TCP:
            proto = "TCP"
            sPort = l4.sport
            dPort = l4.dport

        elif ip.p==dpkt.ip.IP_PROTO_UDP:
            proto = "UDP"
            sPort = l4.sport
            dPort = l4.dport

        elif ip.p==dpkt.ip.IP_PROTO_ICMP:

            icmp = l4
            if icmp.type != 8 and icmp.type != 0:
                #only support icmp Echo(request) and icmp Echo reply
                continue
            proto = "ICMP"
            sPort = 0
            dPort = 0

        else:
            # other protocol not supported
            #print ip.p
            continue
        l4flow =  proto+"_"+srcIP+":"+str(sPort)+"-"+dstIP+":"+str(dPort)

        flowAdded = False
        for flow in l4flowList:
            if flow["l4flow"] == l4flow:
                flow["pkts"].append(pkt)
                flowAdded = True
                break
        if flowAdded == False:
            flow = {"l4flow": l4flow, "pkts": []}
            flow["pkts"].append(pkt)
            l4flowList.append(flow)
            flowAdded = True
        else:
            continue
    return l4flowList

def findCommonFlows(flows1, flows2):
    newFlows1 = []
    newFlows2 = []
    for i, f1 in enumerate(flows1):
        for k, f2 in enumerate(flows2):
            if f1["l4flow"] == f2["l4flow"]:
                newFlows1.append(f1)
                newFlows2.append(f2)
                continue
    return newFlows1, newFlows2


def compareTwoFlows(pktsList1, pktsList2):
    """
    :param pktsList1: the first packet list
    :param pktsList2: the second packet list
    :return: [ pktLost, pktCorrupted ]

    pktLost: list of packets in pktsList1 but not found in pktsList2
    pktCorrupted: list of packets in both pktsList1 and pktsList2 have the same sequence# but payload aren't the same

    Example:
        pktsList1 :   [pk1, pk3, pk4, pk5, pk6, pk7, pk8]
        pktsList2 :   [pk2, pk4, pk5]

        pktLost : [pk3]
        -pk1 is not considered dropped packet, as we start counting from the first common sequence#
            -Reason is we can't guarentee the two packet captures start at the same time.
        -pk2, pk5 are not considered dropped packet as we only compare pktsList1 against pktsList2, not the other way around
        -pk7, pk8 are not considered as dropped packets
            - same reason as pk1 as we can't guarantee the two packet captures are stopped at the same time.
    """
    firstComSeqFound = False
    pktLostTmp = []
    pktLost = []
    pktCorrupted = []

    for p1 in pktsList1:  # p1 supposed to be the longer flow
        #print "Packet#: " + str(p['pktNo'])
        eth1 = dpkt.ethernet.Ethernet(p1['pkt'])
        ip1 = eth1.data
        l41 = ""
        icmp1 = ""
        seq1 = ""
        data1 = ""
        if ip1.p==dpkt.ip.IP_PROTO_UDP:
            #skip UDP
            #UDP does not have sequence number, can't compare.
            continue
        if ip1.p == dpkt.ip.IP_PROTO_TCP:
            l41 = ip1.data
            seq1 = l41.seq
            data1 = l41.data
        elif ip1.p == dpkt.ip.IP_PROTO_ICMP:
            icmp1 = ip1.data
            if icmp1.type != 8 and icmp1.type != 0:
                #only support icmp Echo(request) and icmp Echo reply
                continue
            seq1 = icmp1.echo.seq
            data1 = icmp1.data
        seqFound = False
        for p2  in pktsList2: # p2 supposed to be the shorter flow
            eth2 = dpkt.ethernet.Ethernet(p2['pkt'])
            ip2 = eth2.data
            l42 = ""
            icmp2 = ""
            seq2 = ""
            data1 = ""
            if ip2.p == dpkt.ip.IP_PROTO_UDP:
                # skip UDP
                # UDP does not have sequence number, can't compare.
                continue
            if ip2.p == dpkt.ip.IP_PROTO_TCP:
                l42 = ip2.data
                seq2 = l42.seq
                data2 =l42.data
            elif ip2.p == dpkt.ip.IP_PROTO_ICMP:
                icmp2 = ip2.data
                if icmp2.type != 8 and icmp2.type != 0:
                    # only support icmp Echo(request) and icmp Echo reply
                    continue
                seq2 = icmp2.echo.seq
                data2 = icmp2.data
            if seq2 == seq1:
                seqFound = True
                if not firstComSeqFound:
                    firstComSeqFound = True
                timeElapse = p1['ts'] - p2['ts']
                #print timeElapse
                if len(pktLostTmp) != 0:  # confirm the pktLostTmp are not at the tail of the pcap, so they are valid drops
                    pktLost.extend(pktLostTmp)
                    #print "Confirmed lost " + str(len(pktLostTmp)) + " packets"
                    pktLostTmp = []
                if data1 != data2:
                    pktCorrupted.append(p1)
                continue
        if seqFound == False and firstComSeqFound:
            pktLostTmp.append(p1)  # keep the dropped packets here temporarily because they might be the tail of the pcap(which means the other file have stopped capturing).
            #print "Seq# " + str(seq1) + " might be lost"
        #print "Protocol: " + str(ip.p)
        #print "Sequence: " + str(seq)
        #print ip.p
    return pktLost, pktCorrupted

parser=argparse.ArgumentParser(description='Generate')
parser.add_argument('--file',dest='file', nargs=2,action='store',default=None,help='inputfile')
args=parser.parse_args()

pktList1 = pcapToList(args.file[0])
pktList2 = pcapToList(args.file[1])

flows1 = l4flowPicker(pktList1)
flows2 = l4flowPicker(pktList2)




#trim them down to only common flows
flows1, flows2 = findCommonFlows(flows1, flows2)



for f1 in flows1:
    for f2 in flows2:
        if f1['l4flow'] == f2['l4flow']:
            print "##########################################################################################"
            print "Result for flow: " + f1['l4flow']
            if "UDP" not in f1['l4flow']:
                print "Total number of packets in " + args.file[0] + " : " + str(len(f1['pkts']))
                pktLost, pktCorrupted = compareTwoFlows(f1['pkts'], f2['pkts'])

                print "Packet drops: " + str(len(pktLost)) + "(" + args.file[0] + " against " + args.file[1] + ")"
                for pkt  in pktLost:
                    print "Packet# " + str(pkt['pktNo'])
                print "Total number of packets in " + args.file[1] + " : " + str(len(f2['pkts']))
                pktLost, pktCorrupted = compareTwoFlows(f2['pkts'], f1['pkts'])
                print "Packet drops: " + str(len(pktLost)) + "(" + args.file[1] + " against " + args.file[0] + ")"
                for pkt  in pktLost:
                    print "Packet# " + str(pkt['pktNo'])


            else:
                print "UDP skipped"
    print "##########################################################################################"