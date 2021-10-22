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


def udp_connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    return sock


def req_records(data):
    qname = DNS(data)["DNS Question Record"].qname
    qtype = dns_record(DNS(data)["DNS Question Record"].qtype)
    return qname, qtype


def ssl_connect(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wsock = context.wrap_socket(sock, server_hostname=host)
    wsock.connect((host, 443))
    return wsock


sock = udp_connect(UDP_IP, UDP_PORT)
data, addr = sock.recvfrom(512)
domain, record_type = req_records(data)
print(f"domain: {domain}, record type: {record_type}")

wsock = ssl_connect(DOH_HOST)

request_msg = f"GET /dns-query?name={domain}&type={record_type} HTTP/1.1\r\nAccept: application/dns-json\r\nHost: 1.1.1.1\r\n\r\n"
wsock.send(request_msg.encode())

data = wsock.recv(2048)
print(data)
wsock.close()
