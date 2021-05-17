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
bind_layers(ApipFlag, Apip, flag=1)
bind_layers(ApipFlag, Brief, flag=2)
bind_layers(ApipFlag, Verify, flag=3)

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
        self.iface = get_if()

    def send_drop_flow(self, pkt):
        drop_flow = Apip() # TODO: define drop_flow
        drop_flow = Ether(src=get_if_hwaddr(self.iface), dst=pkt[Ether].src) / drop_flow
        send(drop_flow, verbose=False)

    def send_verified(self, pkt):
        resp = Verify(fingerprint=pkt[Verify].fingerprint, msg_auth=pkt[Verify].msg_auth)
        resp = ApipFlag(flag=ApipFlagNum.VERIFY_RES.value) / resp
        resp = Ether(src=get_if_hwaddr(self.iface), dst=pkt[Ether].src) / resp
        send(resp, verbose=False)

    def respond_pkt(self, pkt):
        if not pkt.haslayer(ApipFlag):
            return

        print_pkt(pkt)
        flag = pkt[ApipFlag].flag

        if flag == ApipFlagNum.BRIEF.value:
            brief = pkt[Brief]
            # TODO: check client valid (bootstrapping)
            bloom_filter = brief.bloom
            blooms_frm_host = self.briefs.get(brief.host_id, set())
            blooms_frm_host.add(bloom_filter)
            self.briefs[brief.host_id] = blooms_frm_host
            print('Added brief from host %s' % brief.host_id)
            # TODO: set 30s timeout action
            return
        
        if flag == ApipFlagNum.VERIFY_REQ.value:
            self.send_verified(pkt) # FOR TESTING
            # 1. Check delegate has received a brief from client containing Fingerprint(pkt)
            fingerprint = pkt[Verify].fingerprint
            client_id = None
            print('Checking self.briefs = %s' % self.briefs)
            for k,v in self.briefs.items():
                if fingerprint in v:
                    client_id = k
                    
            if (client_id is None # TODO: get client_sid
                or client_sid not in self.assigned_sids[client_id] # 2. Check accAddr in pkt is using an SID assigned to client
                or flow_id in self.blocked # 3. Check transmission from S to R has not been blocked via a shutoff
            ):
                print('Fingerprint invalid: Ignored')
                return

            # Return copy of the verification packet signed with private key to verifier V (V will add S -> R to its whitelist).
            # same fingerprint, key = something
            self.send_verified(pkt)
            print('Sent verification reply')

        if flag == ApipFlagNum.SHUTOFF.value:
            self.blocked.add(flow_id)

    def main(self):
        while True:
            print('sniffing')
            sniff(iface=self.iface, prn=self.respond_pkt)

if __name__ == '__main__':
    clients = [socket.gethostbyname(h) for h in sys.argv[1:]]
    print(clients)
    d = Delegate(clients)
    d.main()
