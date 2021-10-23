import socket
import ssl
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP

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
    req_id = DNS(data)["DNS"].id
    return qname, qtype, req_id


def ssl_connect(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wsock = context.wrap_socket(sock, server_hostname=host)
    wsock.connect((host, 443))
    return wsock


def write_to_log(hostname, record_type, isDenied):
    print(f"hostname: {hostname}, record type: {record_type}")
    status = "DENY" if isDenied else "ALLOW"
    f = open("./queries.log", "a")
    f.write(f"{hostname} {record_type} {status}\n")
    f.close()


def isin_deny_list(data, qname, record_type):
    isDenied = False

    decoded_qname = qname.decode("utf-8")
    qname_length = len(decoded_qname)
    hostname = decoded_qname[:qname_length-1]

    with open('deny_list.txt') as f:
        lines = f.readlines()

    for line in lines:
        # check if the flag exists
        if (line == hostname + "\n"):
            isDenied = True
        write_to_log(hostname, record_type, isDenied)
        if isDenied:
            break

    return isDenied


def send_nxdomain(data, req_id):
    # nx = IP(data)
    # nx[DNS] = DNS()
    print(f"data: {data}, req id: {req_id}")


def main():
    sock = udp_connect(UDP_IP, UDP_PORT)
    req_data, addr = sock.recvfrom(512)
    qname, record_type, req_id = req_records(req_data)
    isDenied = isin_deny_list(req_data, qname, record_type)
    if isDenied:
        send_nxdomain(req_data, req_id)

    print(f"Denied: {isDenied}")

    # content_length = len(req_data)
    # req_header = f"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length:{content_length}\r\nHost: 1.1.1.1\r\n\r\n"
    # req = bytes(req_header, 'utf-8') + req_data

    # wsock = ssl_connect(DOH_HOST)

    # wsock.send(req)
    # data = wsock.recv(2048)
    # print(f"data: {data}")
    # data_body = data.split("\r\n\r\n".encode('utf-8'))[1]
    # print(f"body: {data_body}")
    # sock.sendto(data_body, addr)


if __name__ == "__main__":
    main()
