#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from enum import Enum
from threading import Timer

from scapy.all import srp1, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether
from scapy.fields import *
import readline


class ApipFlag(Enum):
    PACKET = 1
    BRIEF = 2
    VERIFY_REQ = 3
    VERIFY_RES = 4
    SHUTOFF = 5

class Apip(Packet):
   fields_desc = [BitField("flag", 0, 4),
                    IPField("src", "127.0.0.1"),
                    IPField("acc", "127.0.0.1")]

bind_layers(Ether, Apip, type=0x87DD)

class Delegate(object):
    BRIEF_PERIOD = 30

    def __init__(self, clients):
        self.clients = set(clients)
        self.assigned_sids = {} # map: clientID -> set/list of sids
        self.briefs = {} # map: clientID -> set of bloom filters
        self.timers = {} # map: clientID -> set of timers
        self.blocked = set() # set of flow identifiers (client_id, dst_ip, client_sid, dst_sid)

    def get_if(self):
        ifs=get_if_list()
        iface=None
        for i in get_if_list():
            if "eth0" in i:
                iface=i
                break
        if not iface:
            print("Cannot find eth0 interface")
            exit(1)
        return iface

    def print_pkt(self, pkt):
        pkt.show2()
        sys.stdout.flush()

    def send_drop_flow(self, pkt):
        drop_flow = Apip() # TODO: define drop_flow
        drop_flow = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) / drop_flow
        send(drop_flow, verbose=False)

    def respond_pkt(self, pkt):
        if not isApip(pkt):
            return
        print_pkt(pkt[0][1])

        flag = pkt[Apip].flag
        acc = pkt[Apip].acc
        # TODO: how to extract
        client_id = None
        dst_ip = None
        client_sid = None
        dst_sid = None        
        flow_id = (client_id, dst_ip, client_sid, dst_sid)

        if flag == ApipFlag.BRIEF: # brief(pkt) = clientID || Fingerprint(pkt) || MAC_K_SD_S(clientID || Fingerprint(pkt))
            # TODO: check client valid, extract bloom_filter
            bloom_filter = None
            self.briefs[flow_id].add(bloom_filter)
            # TODO: set 30s timeout action
            return
        
        if flag == ApipFlag.VERIFY_REQ:
            # 1. Check delegate has received a brief from S containing Fingerprint(pkt)
            if bloom_filter not in self.briefs[client_id]:
                self.send_drop_flow(pkt)
                return
            # 2. Check accAddr in pkt is using an SID assigned to S
            if client_sid not in self.assigned_sids[client_id]:
                self.send_drop_flow(pkt)
                return
            # 3. Check transmission from S to R has not been blocked via a shutoff
            if flow_id in self.blocked:
                self.send_drop_flow(pkt)
                return

            # Return copy of the verification packet signed with private key to verifier V (V will add S -> R to its whitelist).
            # same fingerprint, key = something
            resp = Apip(flag=pkt[Apip].flag, dst=pkt[Apip].src, acc=pkt[Apip].acc)
            resp = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) / resp
            send(resp, verbose=False)

        if flag == ApipFlag.SHUTOFF:
            self.blocked.add(flow_id)

    def main(self):
        iface = self.get_if()
        while True:
            sniff(iface=iface, prn=self.respond_pkt)

if __name__ == '__main__':
    clients = [socket.gethostbyname(h) for h in sys.argv[1]]
    d = Delegate(clients)
    d.main()
