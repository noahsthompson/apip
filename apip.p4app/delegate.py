#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import srp1, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether
from scapy.fields import *
import readline

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class Apip(Packet):
   fields_desc = [ Emph(IPField("srcAddr", "127.0.0.1")),
                   Emph(IPField("dstAddr", "127.0.0.1")),
                   IPField("accAddr", "127.0.0.1")]

bind_layers(Ether, Apip, type=0x9999)

def print_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()

def isApip(pkt):
    pkt.hasLayer(Apip)

def isBrief(pkt):
    return False

def isVerify(pkt):
    return False

def isShutoff(pkt):
    return False

def respond_pkt(pkt):
    if not isApip(pkt):
        return
    print_pkt(pkt[0][1])
    if isBrief(pkt):
        # brief(pkt) = clientID || Fingerprint(pkt) || MAC_K_SD_S(clientID || Fingerprint(pkt))
        pass
    elif isVerify(pkt):
        # check:
        # 1. delegate has received a brief from S containing Fingerprint(pkt)
        # 2. accAddr in pkt is using an SID assigned to S
        # 3. transmission from S to R has not been blocked via a shutoff

        # OK: return a copy of the verification packet signed with its private key to verifier (it will add S -> R to its whitelist).
        resp = Apip(src=p[IP].dst, dst=p[IP].src)
        send(resp, verbose=False)
    elif isShutoff(pkt):
        # shutoff the flow that pkt is from
        pass



def main():
    iface = get_if()
    while True:
        sniff(iface=iface, prn=respond_pkt)

    # src, dst = socket.gethostbyname(sys.argv[1]), socket.gethostbyname(sys.argv[2])
    # pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / Apip(dstAddr=dst, accAddr=dst, result = 0)

if __name__ == '__main__':
    main()
