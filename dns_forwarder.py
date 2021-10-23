import socket
import ssl
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
import json
import subprocess
import sys
import base64

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
    src = IP(data)["IP"].src
    sport = UDP(data)["UDP"].sport
    return qname, qtype, src, sport


def ssl_connect(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wsock = context.wrap_socket(sock, server_hostname=host)
    wsock.connect((host, 443))
    return wsock


def main():
    sock = udp_connect(UDP_IP, UDP_PORT)
    req_data, addr = sock.recvfrom(512)

    content_length = len(req_data)
    req_header = f"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length:{content_length}\r\nHost: 1.1.1.1\r\n\r\n"
    req = bytes(req_header, 'utf-8') + req_data

    wsock = ssl_connect(DOH_HOST)

    wsock.send(req)
    data = wsock.recv(2048)
    print(f"data: {data}")
    data_body = data.split("\r\n\r\n".encode('utf-8'))[1]
    print(f"body: {data_body}")
    sock.sendto(data_body, addr)


if __name__ == "__main__":
    main()
