import socket
import ssl
from scapy.all import DNS, DNSQR, sr1, IP, UDP
import argparse
import base64
import requests

parser = argparse.ArgumentParser(
    description="Run a DNS forwarder to forward your request to a DoH server")
parser.add_argument('-d', type=str, metavar='', dest='DST_IP',
                    help='Destination DNS server IP')
parser.add_argument('-f', type=str, metavar='', dest='DENY_LIST', default='deny_list.txt',
                    help='DENY_LIST_FILE containing domains to block')
parser.add_argument('-l', type=str, metavar='', dest='QUERIES_LOG', default='./queries.log',
                    help='LOG_FILE Append-only log file')
parser.add_argument('--doh', dest='DOH', action='store_true',
                    help='Use default upstream DoH server')
parser.add_argument('--doh_server', type=str, metavar='', dest='DOH_SERVER',
                    help='User this upstream DoH server')

args = parser.parse_args()

UDP_PORT = 53
UDP_IP = '127.0.0.1'
DST_IP = args.DST_IP
DST_PORT = 80
DOH_SERVER = '1.1.1.1'

# Use the specified DoH server if specified; if not, use the default upstream DoH server
if (args.DOH_SERVER != None):
    DOH_SERVER = args.DOH_SERVER

if (args.DOH == False and args.DOH_SERVER == None and args.DST_IP == None):
    print("If --doh and --doh_server are not specified, -d MUST be present")
    exit(0)


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
    qtype = DNS(data)["DNS Question Record"].qtype
    req_id = DNS(data)["DNS"].id
    return hostname, qtype, req_id


def ssl_connect(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wsock = context.wrap_socket(sock, server_hostname=host)
    wsock.connect((host, 443))
    return wsock


def write_to_log(hostname, record_type, isDenied):
    status = "DENY" if isDenied else "ALLOW"
    f = open(args.QUERIES_LOG, "a")
    f.write(f"{hostname} {record_type} {status}\n")
    f.close()


def isin_deny_list(hostname, record_type):
    isDenied = False

    with open(args.DENY_LIST) as f:
        lines = f.readlines()

    for line in lines:
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


def dns_forward(req_data):
    sock = udp_connect("127.0.0.1", 17777)
    sock.sendto(req_data, ("1.1.1.1", 53))
    data = sock.recvfrom(512)
    print(data)

    return data


def doh_forward(hostname, record_type, req_id):
    dns_req = DNS(id=0, qd=DNSQR(qname=hostname, qtype=record_type),
                  an=None, ns=None, ar=None)

    dns_req_bytes = bytes(dns_req)
    b64 = base64.urlsafe_b64encode(dns_req_bytes)
    b64url = b64.decode('utf-8').split('=')[0]

    params_dict = {'dns': b64url}
    headers_dict = {'Accept': 'application/dns-message'}
    url = f'https://{DOH_SERVER}/dns-query'
    data = requests.get(
        url,
        params=params_dict,
        headers=headers_dict,
    )
    response = DNS(data.content)
    response[DNS].id = req_id

    return bytes(response)


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
                data = dns_forward(req_data)
            else:
                data = doh_forward(hostname, record_type, req_id)

            sock.sendto(data, addr)


if __name__ == "__main__":
    main()
