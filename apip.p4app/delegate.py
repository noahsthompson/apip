#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from enum import Enum
from threading import Timer

# from scapy.all import srp1, sniff, get_if_list, get_if_hwaddr, bind_layers
# from scapy.all import Packet
# from scapy.all import Ether
# from scapy.fields import *
from scapy.all import *
import readline


class ApipFlagNum(Enum):
    PACKET = 1
    BRIEF = 2
    VERIFY_REQ = 3
    VERIFY_RES = 4
    SHUTOFF = 5

class ApipFlag(Packet):
   fields_desc = [BitField("flag", 0, 8)]

class Apip(Packet):
   fields_desc = [
       BitField("accAddr", 0, 16),
       BitField("retAddr", 0, 16),
       IPField("dstAddr", "127.0.0.1")
   ]

class Brief(Packet):
   fields_desc = [
       BitField("host_id", 0, 48),
       BitField("bloom", 0, 64)
   ]

class Verify(Packet):
   fields_desc = [
       BitField("fingerprint", 0, 64),
       BitField("msg_auth", 0, 64)
   ]

bind_layers(Ether, ApipFlag, type=0x87DD)

def get_if():
    ifs=get_if_list()
    print(ifs)
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def print_pkt(pkt):
    pkt = pkt[0][1]
    pkt.show2()
    sys.stdout.flush()

class Delegate(object):
    BRIEF_PERIOD = 30

    def __init__(self, clients):
        self.clients = set(clients)
        self.assigned_sids = {} # map: clientID -> set/list of sids
        self.briefs = {} # map: clientID -> set of bloom filters
        self.timers = {} # map: clientID -> set of timers
        self.blocked = set() # set of flow identifiers (client_id, dst_ip, client_sid, dst_sid)

    def send_drop_flow(self, pkt):
        drop_flow = Apip() # TODO: define drop_flow
        drop_flow = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) / drop_flow
        send(drop_flow, verbose=False)

    def send_verified(self, pkt):
        resp = Verify(fingerprint=pkt[Verify].fingerprint, msg_auth=pkt[Verify].msg_auth)
        resp = ApipFlag(flag=pkt[ApipFlag].flag) / resp
        resp = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) / resp
        send(resp, verbose=False)

    def _get_layers(self,pkt):
        counter = 0
        while True:
            layer = pkt.getlayer(counter)
            if layer is None:
                break

            yield layer
            counter += 1

    def respond_pkt(self, pkt):
        for l in self._get_layers(pkt):
            print(l.name)
        print_pkt(pkt)
        
        flag = pkt[ApipFlag].flag

        if flag == ApipFlagNum.BRIEF.value:
            brief = Brief(pkt[Raw].load)
            # TODO: check client valid (bootstrapping)
            bloom_filter = brief.bloom
            self.briefs[brief.host_id].add(bloom_filter)
            # TODO: set 30s timeout action
            return
        
        if flag == ApipFlagNum.VERIFY_REQ.value:
            verify = Verify(pkt[Raw].load)
            self.send_verified(verify) # FOR TESTING
            # 1. Check delegate has received a brief from client containing Fingerprint(pkt)
            fingerprint = pkt[Verify].fingerprint
            client_id = None
            for k,v in self.briefs:
                if fingerprint in v:
                    client_id = k
                    
            if client_id is None:
                self.send_drop_flow(pkt)
                return
            # 2. Check accAddr in pkt is using an SID assigned to client
            # TODO: get client_sid
            if client_sid not in self.assigned_sids[client_id]:
                self.send_drop_flow(pkt)
                return
            # 3. Check transmission from S to R has not been blocked via a shutoff
            if flow_id in self.blocked:
                self.send_drop_flow(pkt)
                return

            # Return copy of the verification packet signed with private key to verifier V (V will add S -> R to its whitelist).
            # same fingerprint, key = something
            self.send_verified(pkt)

        if flag == ApipFlagNum.SHUTOFF.value:
            self.blocked.add(flow_id)

    def main(self):
        iface = get_if()
        while True:
            print('sniffing')
            sniff(iface=iface, prn=self.respond_pkt)

if __name__ == '__main__':
    clients = [socket.gethostbyname(h) for h in sys.argv[1:]]
    print(clients)
    d = Delegate(clients)
    d.main()
