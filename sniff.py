#!/usr/bin/env python
import scapy.all as scapy

def psniff(interface):
    scapy.sniff(iface=interface, store=False, prn=see_packets, filter="tcp")    #"udp", "port 21", "ftp" etc..

def see_packets(packet):
    print(packet)

psniff("eth0")