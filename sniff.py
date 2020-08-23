#!/usr/bin/env python
import scapy.all as scapy

def psniff(interface):
    scapy.sniff(iface=interface, store=False, prn=see_packets)

def see_packets(packet):
    print(packet)

psniff("eth0")