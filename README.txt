#PACKET_sniffer

#Required python MODULES
scapy.all
scapy_http
optparse
argparse (for python3)

**NOTE:
If your using this tool to intercept and capture data form a remote machine then..
>You have to be in the middle of the connect to intercept the RAW packets (use https://github.com/gouthamk-cryptichub/ARP_spoofer to become MITM)
>IP forwarding should be enabled in your machine
    Open TERMINAL
    >echo 1 > /proc/sys/net/ipv4/ip_forward [ENTER]