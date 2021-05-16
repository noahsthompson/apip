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

from delegate import ApipFlagNum, ApipFlag, Apip, Brief, get_if, print_pkt

bind_layers(Ether, ApipFlag, type=0x87DD)

def main():
    if len(sys.argv)<3:
        print('usage: host.py <source> <destination> <delegate>')
        exit(1)
    iface = get_if()
    src = socket.gethostbyname(sys.argv[1])
    dst = socket.gethostbyname(sys.argv[2])
    print("sending on interface %s for %s <-> %s traffic" % (iface, src, dst))

    # build packet
    acc_quadrants = socket.gethostbyname(sys.argv[3]).split('.')
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / ApipFlag(flag=ApipFlagNum.PACKET)
    pkt = pkt / Apip(accAddr='.'.join(acc_quadrants[:2]), retAddr='.'.join(acc_quadrants[2:]), dstAddr=dst)
    
    # send brief
    brf = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    brf = brf / ApipFlag(flag=ApipFlagNum.BRIEF)
    brf = brf / Brief(host_id=sys.argv[1], bloom=0)
    
    sendp(pkt)
    sendp(brf)
    # pkt = srp1(pkt, iface=iface, verbose=False)
    # print_pkt(pkt[0][1])    

if __name__ == '__main__':
    main()
