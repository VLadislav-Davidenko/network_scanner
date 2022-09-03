#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    """Adding parser to take ip address from terminal. Option that will be called is -t or --target
        and its argument is ip, save ip that entered user in options.ip and use it in our code"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help=" Your targeted ip ")
    options = parser.parse_args()

    # Checking if user enter the ip
    if not options.ip:
        parser.error("[-] Please enter the target (ip), for more info enter -help")
        return None
    else:
        return options.ip


def scan(ip):
    # scapy.arping(ip) - The easiest way to get a MAC address via ARP request
    # print(arp_request.summary()) - Getting ARP package that we are going to send
    # scapy.ls(scapy.ARP()) - Getting all information about this class

    arp_request = scapy.ARP(pdst=ip)

    # arp_request.show() - Show a whole info about a package
    """ We set destination in broadcast to ff:ff:ff:ff:ff:ff because we want to send question
    to all MAC addresses in network 'one to all' - one of the types of broadcasts in IPV4
    There are two of them: Limited broadcast and Directed broadcast."""
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combining ARP and broadcast in one package
    arp_request_broadcast = broadcast / arp_request

    # Sending request and getting list of answered and unanswered (Timeout - time we can wait)
    # Verbose - hide information such as Received packets, got
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Here we create a list of dictionaries with keys: "id" and "mac" and their value
    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


# Simple function to return a table of given results
def print_result(results_list):
    print("   IP\t\t\t\t  MAC address\n-----------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t\t" + client["mac"])


ip_address = get_arguments()
scan_results = scan(ip_address)
print_result(scan_results)
