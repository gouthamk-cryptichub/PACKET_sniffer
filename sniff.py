#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
def psniff(interface):
    scapy.sniff(iface=interface, store=False, prn=see_packets)

def see_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)

psniff("eth0")