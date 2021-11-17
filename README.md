# DNS Forwarder

A simple DNS forwarder with domain blocking and DoH capabilities. This DNS forwarder will need to do the following: (1) receive an arbitrary DNS message from a client (dig command), (2) check if the domain name should be blocked, and if so respond with an NXDomain message, (3) if the queried domain name is allowed, forward the DNS message to either standard DNS resolver or a DoH-capable resolver, (4) wait for the response from the resolver and forward it back to the client.

## Command Line Parameters:
```
$ ./dns_forwarder.py -h
usage: dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE 
                        [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]

optional arguments:
-h, --help   show this help message and exit
-d   DST_IP Destination DNS server IP
-f   DENY_LIST_FILE File containing domains to block
-l   LOG_FILE Append-only log file
--doh   Use default upstream DoH server
--doh_server DOH_SERVER  Use this upstream DoH server
```
## Requirements:
* If --doh or --doh_server are specified, the forwarder MUST forward the DNS query using the DoH protocol
* If neither --doh nor --doh_server are specified (in which case -d MUST be present), the forwarder MUST forward the DNS query using the DNS protocol
* When DoH is not used, the -d option will be specified and the forwarder must use a simple UDP client socket to forward the client's query to the DNS resolver

## Log File Entry Format
The log file is a text file containing a record of all domain names and query types that have been requested, and whether the request was blocked or allowed. For instance:
```
www.google.com A ALLOW
google.com NS ALLOW
www.yahoo.co.jp A DENY
yahoo.co.jp MX DENY
www.youtube.com A ALLOW
www.example.com A DENY
```
