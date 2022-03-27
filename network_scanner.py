#!/usr/bin/env python

from scapy.all import *
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP range")
    options = parser.parse_args()
    return options


def scan(ip):
    print("[+] Scanning IP " + ip)
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []

    for answered_element in answered_list:
        client_dict = {"ip": answered_element[1].psrc, "mac": answered_element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_argument()

scan_result = scan(options.target)
print_result(scan_result)
