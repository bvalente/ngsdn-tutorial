#!/usr/bin/python

#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse, time, threading

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.link import Intf
from mininet.topo import Topo
from stratum import StratumBmv2Switch

CPU_PORT = 255

# Perform ARP Reply every 30 sec
def scheduleArpReply(host, int, ip):
    while(True):
        time.sleep(30)
        try:
            host.cmd('arping -P -i %s -U %s &> /dev/null &' % (intf, ip))
        except Exception:
            pass


class IPv4Host(Host):
    """Host that can be configured with an IPv4 gateway (default route).
    """


    def config(self, mac=None, ip=None, defaultRoute=None, lo='up', gw=None,
               **_params):
        super(IPv4Host, self).config(mac, ip, defaultRoute, lo, **_params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -4 link set up %s' % self.defaultIntf())
        self.cmd('ip -4 addr add %s dev %s' % (ip, self.defaultIntf()))
        if gw:
            self.cmd('ip -4 route add default via %s' % gw)
            threading.Thread(target=scheduleArpReply, args=(self, self.defaultIntf(), ip,)).start() #make non-blocking

        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (
                self.defaultIntf(), attr)
            self.cmd(cmd)

        def updateIP():
            return ip.split('/')[0]

        self.defaultIntf().updateIP = updateIP


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv4 hosts"""

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Leaves
        # gRPC port 50001
        leaf1 = self.addSwitch('leaf1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50002
        leaf2 = self.addSwitch('leaf2', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50003
        leaf3 = self.addSwitch('leaf3', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # Spines
        # gRPC port 50004
        spine1 = self.addSwitch('spine1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50005
        spine2 = self.addSwitch('spine2', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50006
        spine3 = self.addSwitch('spine3', cls=StratumBmv2Switch, cpuport=CPU_PORT)


        # Switch Links
        self.addLink(spine1, leaf1)
        self.addLink(spine1, leaf2)
        self.addLink(spine2, leaf1)
        self.addLink(spine2, leaf2)
        # extended
        self.addLink(spine1, leaf3) #update spine1
        self.addLink(spine2, leaf3) #update spine2
        self.addLink(spine3, leaf1)
        self.addLink(spine3, leaf2)
        self.addLink(spine3, leaf3)

        # IPv4 hosts attached to leaf 1
        h1 = self.addHost('h1', cls=IPv4Host, mac="00:00:00:00:00:10",
                           ip='10.10.0.1/16', gw='10.10.0.254')
        h2 = self.addHost('h2', cls=IPv4Host, mac="00:00:00:00:00:20",
                           ip='10.20.0.2/16', gw='10.20.0.254')
        self.addLink(h1, leaf1)  # port 3
        self.addLink(h2, leaf1)  # port 4

        # extended
        # IPv4 hosts attached to leaf 3
        h3 = self.addHost('h3', cls=IPv4Host, mac="00:00:00:00:00:30",
                          ip='10.10.0.3/16', gw='10.10.0.254')
        self.addLink(h3, leaf3)  # port 3


def addNAT(net):
    """Custom node with dedicated interface and iptable rules"""

    subnet = '10.20.0.0/16'
    inetIntf = 'eth1'
    inetIp = '172.16.100.2'
    lanIntf = ''
    lanIp = '10.20.0.254'

    nat = net.addHost('nat')
    net.addLink('leaf2', nat)
    Intf(inetIntf, nat)
    
    lanIntf = nat.defaultIntf()

    # Configure lan interface
    nat.cmd('ip -4 addr flush dev %s' % lanIntf)
    nat.cmd('ip -6 addr flush dev %s' % lanIntf)
    nat.cmd('ip -4 link set up %s' % lanIntf)
    nat.cmd('ip addr add %s/16 dev %s' % (lanIp, lanIntf))

    # Configure inet interface
    nat.cmd('ip -4 addr flush dev %s' % inetIntf)
    nat.cmd('ip -6 addr flush dev %s' % inetIntf)
    nat.cmd('ip -4 link set up %s' % inetIntf)
    nat.cmd('ip addr add %s/24 dev %s' % (inetIp, inetIntf))

    # default route
    nat.cmd('ip route add default via 172.16.100.1 dev %s' % inetIntf)

    # periodic arp
    threading.Thread(target=scheduleArpReply, args=(nat, nat.defaultIntf(), lanIp)).start()

    # Instruct the kernel to perform forwarding
    nat.cmd('sysctl net.ipv4.ip_forward=1' )

    # Flush any currently active rules
    nat.cmd('iptables -F')
    nat.cmd('iptables -t nat -F')
    # Create default entries for unmatched traffic
    nat.cmd('iptables -P INPUT ACCEPT')
    nat.cmd('iptables -P OUTPUT ACCEPT')
    nat.cmd('iptables -P FORWARD DROP')

    # Install NAT rules
    nat.cmd('iptables -I FORWARD',
            '-i', nat.defaultIntf(), '-d', subnet, '-j DROP')
    nat.cmd('iptables -A FORWARD',
            '-i', nat.defaultIntf(), '-s', subnet, '-j ACCEPT')
    nat.cmd('iptables -A FORWARD',
            '-i', inetIntf, '-d', subnet, '-j ACCEPT')
    nat.cmd('iptables -t nat -A POSTROUTING',
            '-o', inetIntf, '-s', subnet, '-j MASQUERADE')

    # Disable offload
    for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (
                nat.defaultIntf(), attr)
            nat.cmd(cmd)


def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
    addNAT(net)
    net.start()
    CLI(net)
    net.stop()
    print '#' * 80
    print 'ATTENTION: Mininet was stopped! Perhaps accidentally?'
    print 'No worries, it will restart automatically in a few seconds...'
    print 'To access again the Mininet CLI, use `make mn-cli`'
    print 'To detach from the CLI (without stopping), press Ctrl-D'
    print 'To permanently quit Mininet, use `make stop`'
    print '#' * 80


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv4 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()
