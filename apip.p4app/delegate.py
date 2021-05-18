#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from enum import Enum
from threading import Timer

from scapy.all import *
import readline


class ApipFlagNum(Enum):
    PACKET = 1
    BRIEF = 2
    VERIFY_REQ = 3
    VERIFY_RES = 4
    TIMEOUT = 5
    SHUTOFF = 6

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

class Shutoff(Packet):
   fields_desc = [
       BitField("fingerprint", 0, 64),
       BitField("msg_auth", 0, 64)
   ]

class Timeout(Packet):
   fields_desc = [
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
    BRIEF_PERIOD = 30.0

    def __init__(self, clients):
        self.clients = set(clients)
        self.assigned_sids = {} # map: clientID -> set/list of sids
        self.client_to_briefs = {} # map: clientID -> set of fingerprints
        self.brief_to_client = {} # map: fingerprint -> clientID
        self.timers = {} # map: clientID -> timer
        self.blocked = set() # set of flow identifiers (client_id, dst_ip, client_sid, dst_sid)
        self.iface = get_if()

    def brief_timeout(self, client_id):
        print('Timer expired: Removing host %s' % client_id)
        self.brief_to_client = {k:v for k,v in self.brief_to_client.items() if v != client_id}
        del self.client_to_briefs[client_id]
        del self.timers[client_id]
        tm = Timeout()
        tm = ApipFlag(flag=ApipFlagNum.TIMEOUT.value) / tm
        tm = Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff') / tm
        sendp(tm, verbose=False)

    def send_verified(self, pkt):
        resp = Verify(fingerprint=pkt[Verify].fingerprint, msg_auth=pkt[Verify].msg_auth)
        resp = ApipFlag(flag=ApipFlagNum.VERIFY_RES.value) / resp
        resp = Ether(src=get_if_hwaddr(self.iface), dst=pkt[Ether].src) / resp
        sendp(resp, verbose=False)

    def respond_pkt(self, pkt):
        if not pkt.haslayer(ApipFlag):
            return

        print_pkt(pkt)
        flag = pkt[ApipFlag].flag

        if flag == ApipFlagNum.BRIEF.value:
            brief = pkt[Brief]
            # reset timer
            host_id = brief.host_id
            if host_id in self.timers:
                self.timers[host_id].cancel()
            timer = Timer(Delegate.BRIEF_PERIOD, self.brief_timeout, [host_id])
            self.timers[host_id] = timer
            timer.start()

            # save brief
            bloom_filter = brief.bloom
            blooms_frm_host = self.client_to_briefs.get(host_id, set())
            blooms_frm_host.add(bloom_filter)
            self.client_to_briefs[host_id] = blooms_frm_host
            print('Added brief from host %s' % host_id)
            return
        
        if flag == ApipFlagNum.VERIFY_REQ.value:
            self.send_verified(pkt) # FOR TESTING
            # Check delegate has received a brief from client containing Fingerprint(pkt)
            fingerprint = pkt[Verify].fingerprint
            client_id = self.brief_to_client.get(fingerprint)

            # Check transmission from S to R has not been blocked via a shutoff  
            if (fingerprint in self.blocked):
                print('Flow blocked: Dropping')
                return

            # Return copy of the verification packet signed with private key to verifier V (V will add S -> R to its whitelist).
            # same fingerprint, key = something
            self.send_verified(pkt)
            print('Sent verification reply')
            return

        if flag == ApipFlagNum.SHUTOFF.value:
            fingerprint = pkt[Shutoff].fingerprint
            self.blocked.add(fingerprint)

    def main(self):
        while True:
            print('sniffing')
            sniff(iface=self.iface, prn=self.respond_pkt)

if __name__ == '__main__':
    clients = [socket.gethostbyname(h) for h in sys.argv[1:]]
    print(clients)
    d = Delegate(clients)
    d.main()
