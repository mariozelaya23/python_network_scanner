#!/usr/bin/env python

from scapy.all import *


def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n------------------------------------------------")
    client_list = []
    for answered_element in answered_list:
        client_dict = {"ip": answered_element[1].psrc, "mac": answered_element[1].hwsrc}
        client_list.append(client_dict)
        # print(answered_element[1].psrc + "\t\t" + answered_element[1].hwsrc)
    print(client_list)


scan("192.168.2.1/24")

