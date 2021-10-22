import socket
import ssl
import base64
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
import json
import subprocess
import sys

UDP_PORT = 53
UDP_IP = "127.0.0.1"
DOH_HOST = '1.1.1.1'


def dns_record(dns_id):
    if (dns_id == 1):
        return 'A'
    elif (dns_id == 28):
        return 'AAAA'


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

data, addr = sock.recvfrom(512)
qname = DNS(data)["DNS Question Record"].qname
qtype = dns_record(DNS(data)["DNS Question Record"].qtype)
print(f"qname: {qname}, qtype: {qtype}")

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
wsock = context.wrap_socket(sock, server_hostname=DOH_HOST)
wsock.connect((DOH_HOST, 443))

request_msg = f"GET /dns-query?name={qname}&type={qtype} HTTP/1.1\r\nAccept: application/dns-json\r\nHost: 1.1.1.1\r\n\r\n"
wsock.send(request_msg.encode())

data = wsock.recv(2048)
print(data)
wsock.close()
