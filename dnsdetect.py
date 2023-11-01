import sys
import argparse
import netifaces as nif
from scapy.all import *

response_data = {}

def dns_detect(pckt):
    tcp = False
    udp = False
    if pckt.haslayer(IP):
        src_ip = pckt[IP].src
        
        dest_ip = pckt[IP].dst
        
        if pckt.haslayer(TCP) or pckt.haslayer(UDP):
            if pckt.haslayer(DNS) and pckt.haslayer(DNSRR) and pckt[DNS].qr == 1:
                dns_id = pckt[DNS].id
                #print("id: " + str(dns_id))
                dns_qd = pckt[DNS].qd

                dns_qname = dns_qd.qname

                #checks if the response data has any packets info stored
                if len(response_data) != 0:
                    if dns_id in response_data:

                        data = response_data[dns_id]
                        if data[IP].src == src_ip and data[IP].dst == dest_ip \
                                and data[DNS].qd.qname == dns_qname \
                                and data[DNSRR].rdata != pckt[DNSRR].rdata:
                            print (time.strftime("%Y-%m-%d %H:%M") + " DNS poisoning attempt")
                            print ("TXID [%s] Request [%s]"%(data[DNS].id, data[DNS].qd.qname.rstrip('.')))
                            print ("Answer1 "),

                            for rrcnt in range(data[DNS].ancount):
                                if data[DNS].an[rrcnt].type == 1:

                                    dnsrr = data[DNS].an[rrcnt]
                                    print ("[%s] "%dnsrr.rdata),
                            print ('\b')
                            print ("Answer2 "),
                            
                            for rrcnt in range(pckt[DNS].ancount):
                                if pckt[DNS].an[rrcnt].type == 1:
                                    dnsrr = pckt[DNS].an[rrcnt]
                                    print ("[%s] "%dnsrr.rdata),
                            
                            print ('\b')
                else:
                    #store packet value 
                    response_data[dns_id] = pckt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    local_interface = nif.gateways()['default'][nif.AF_INET][1]
    parser.add_argument("-i", "--interface")
    parser.add_argument("-r", "--tracefile")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter")
    args = parser.parse_args()
    if args.tracefile != None:
        sniff(filter=str(args.expr), offline=str(args.tracefile), store=0, prn=dns_detect)
    elif args.interface != None:
        sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=dns_detect)
    else:
        sniff(filter=str(args.expr), store=0, prn=dns_detect)