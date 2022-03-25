#!/usr/bin/env python

from scapy.all import *


def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    arp_request.show()
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    arp_request_broadcast.show()


scan("192.168.2.1/24")

