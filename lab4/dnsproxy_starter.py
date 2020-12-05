#!/usr/bin/env python
import argparse
import socket
# from scapy.all import *

# This is going to Proxy in front of the Bind Server
# bind_server_ip = '127.0.0.1'
# bind_server_port = 1053


parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
HOST = "127.0.0.1"
PORT = args.port # defailt 8087
# BIND's port
DNS_ADDR = "127.0.0.1"
DNS_PORT = args.dns_port # we set to 5050
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

print(PORT)
print(DNS_PORT)
print(SPOOF)

def forward_to_dns(data, serv, dig_addr, dig_port):
    # new packet = scapy create packet with data, host, port
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)

    client.sendto(data, (DNS_ADDR, DNS_PORT))

    response_data = ""
    while True:
        try:
            response_data, (response_addr, response_port) = client.recvfrom(4096)
        except:
            break
        if not response_data:
            break
        print("response_data", response_data)
        print("response_addr", response_addr)
        print("response_port", response_port)
        serv.sendto(response_data, (dig_addr, dig_port))
    client.close()


serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM )
serv.bind((HOST, PORT))

while True:
    while True:
        data, (addr, port) = serv.recvfrom(4096)
        if not data:
            break
        print("data", data)
        print("addr", addr)
        print("port", port)
        forward_to_dns(data, serv, addr, port)

    serv.close()
    print('client disconnected')


