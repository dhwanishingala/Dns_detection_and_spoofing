import sys
import argparse
import socket
import netifaces as nif
from scapy.all import *

data_q = deque(maxlen = 20)
#print(data_q)
def dns_detect(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
        if len(data_q)>0:
            for op in data_q:
                #op.show()
                if (op[IP].dst == pkt[IP].dst and\
                op[IP].sport == pkt[IP].sport and\
                op[IP].dport == pkt[IP].dport and\
                op[DNSRR].rdata != pkt[DNSRR].rdata and\
                op[DNS].id == pkt[DNS].id and\
                op[DNS].qd.qname == pkt[DNS].qd.qname and\
                op[IP].payload != pkt[IP].payload):
                    #print(op[DNS].qd.qname.decode('utf-8'))
                    print ("DNS poisoning attempt detected")
                    print ("TXID %s Request URL %s"%( op[DNS].id, op[DNS].qd.qname.decode('utf-8')))
                    print ("Answer1 [%s]"%op[DNSRR].rdata)
                    print ("Answer2 [%s]"%pkt[DNSRR].rdata)
        data_q.append(pkt)
  
if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    local_interface = nif.gateways()['default'][nif.AF_INET][1]
    print("local: " + local_interface)
    parser.add_argument("-i", "--interface")
    parser.add_argument("-r", "--injectionfile")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter")
    args = parser.parse_args()
    print(args)
    #print(args.interface)
    if args.injectionfile != None:
        print ("Sniffing from the tracefile")
        sniff(filter=str(args.expr), offline=str(args.injectionfile), store=0, prn=dns_detect)
    elif args.interface != None:
        print ("Sniffing from the interface" )
        sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=dns_detect)
    else:
        print ("Enter file or interface for sniffing")
        # sniff(filter=str(args.expr), store=0, prn=dns_detect)