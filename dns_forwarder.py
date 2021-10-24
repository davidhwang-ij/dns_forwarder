import socket
import ssl
from scapy.all import DNS, DNSQR
import argparse

parser = argparse.ArgumentParser(
    description="Run a DNS forwarder to forward your request to a DoH server")
parser.add_argument('-d', type=str, metavar='', dest='DST_IP',
                    help='Destination DNS server IP')
parser.add_argument('-f', type=str, metavar='', default='deny_list.txt',
                    help='DENY_LIST_FILE containing domains to block')
parser.add_argument('-l', type=str, metavar='', default='./queries.log',
                    help='LOG_FILE Append-only log file')
parser.add_argument('--doh', type=bool, metavar='', dest='DOH', default=False,
                    help='Use default upstream DoH server')
parser.add_argument('--doh_server', type=str, metavar='', dest='DOH_SERVER',
                    help='User this upstream DoH server')

args = parser.parse_args()

UDP_PORT = 53
UDP_IP = '127.0.0.1'
DST_IP = args.DST_IP
DOH_SERVER = args.DOH_SERVER if args.DOH_SERVER != None else '1.1.1.1'
# if only DOH is specified???

# Handle Flag Errors
if (args.DOH == False and args.DOH_SERVER == None and args.DST_IP == None):
    print("If --doh and --doh_server are not specified, you must specify your -d")
    exit(0)


def dns_record(dns_id):
    if (dns_id == 1):
        return 'A'
    elif (dns_id == 28):
        return 'AAAA'


def udp_connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    return sock


def decode_qname(qname):
    decoded_qname = qname.decode("utf-8")
    qname_length = len(decoded_qname)
    hostname = decoded_qname[:qname_length-1]
    return hostname


def req_records(data):
    qname = DNS(data)["DNS Question Record"].qname
    hostname = decode_qname(qname)
    qtype = dns_record(DNS(data)["DNS Question Record"].qtype)
    req_id = DNS(data)["DNS"].id
    return hostname, qtype, req_id


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


def isin_deny_list(hostname, record_type):
    isDenied = False

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


def nxdomain(hostname, record_type, req_id):
    nx = DNS(id=req_id, qr=0, opcode="QUERY",
             rd=1, ra=0, ad=1, rcode=3,
             ancount=0, nscount=0, arcount=1,
             qd=DNSQR(qname=hostname, qtype=record_type),
             an=None, ns=None, ar=None)
    return bytes(nx)


def udp_forward(req_data):
    sock = udp_connect(UDP_IP, 12345)
    sock.sendto(req_data, (DST_IP, UDP_PORT))
    data, _ = sock.recvfrom(512)

    return data


def doh_forward(req_data):
    content_length = len(req_data)
    req_header = f"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length:{content_length}\r\nHost: 1.1.1.1\r\n\r\n"
    req = bytes(req_header, 'utf-8') + req_data

    wsock = ssl_connect(DOH_SERVER)
    wsock.send(req)
    data = wsock.recv(2048)
    print(f"data: {data}")
    data_body = data.split("\r\n\r\n".encode('utf-8'))[1]

    return data_body


def main():
    sock = udp_connect(UDP_IP, UDP_PORT)
    while True:
        req_data, addr = sock.recvfrom(512)
        hostname, record_type, req_id = req_records(req_data)
        isDenied = isin_deny_list(hostname, record_type)

        if isDenied:
            nx = nxdomain(hostname, record_type, req_id)
            sock.sendto(nx, addr)
        else:
            if (args.DOH == False and args.DOH_SERVER == None):
                # send over DNS
                data = udp_forward(req_data)
            else:
                data = doh_forward(req_data)

            sock.sendto(data, addr)


if __name__ == "__main__":
    main()
