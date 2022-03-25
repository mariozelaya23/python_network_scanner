#!/usr/bin/env python
import scapy.all
from scapy.all import *


def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1)[0]
    print(answered_list.summary())

    for answered_element in answered_list:
        print(answered_element[1].psrc)
        print(answered_element[1].hwsrc)
        print("--------------------------------------------------------------------------------")


scan("192.168.2.1/24")

