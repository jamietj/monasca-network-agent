# stdlib
from __future__ import division

import logging
import re
import psutil
import threading
import random
import time
import Queue
import math
import subprocess
import sys
import pcap
import socket
import dpkt
import datetime

# project
import monasca_agent.collector.checks as checks

log = logging.getLogger(__name__)

class NetworkStats(checks.AgentCheck):

    #
    #
    def ip_to_str(self, ip):
        return socket.inet_ntop(socket.AF_INET, ip)

    #
    #
    def entropy(self, dist):
        _sum = 0
        entropy = 0

        for num in dist.values():
            _sum += num

        prob = []

        for num in dist.values():
            prob.append(num/_sum)

        for probability in prob:
            entropy -= probability * math.log(probability) / math.log(2)

        return entropy
    
    #
    #
    def resetStats(self, stats):
        stats['startTime']      = 0
        stats['bytecnt']        = 0
        stats['packetcnt']      = 0
        stats['activeflows']    = 0
        stats['flows']          = []
        stats['bytecntdist']    = {}
        stats['srcportdist']    = {}
        stats['dstportdist']    = {}
        stats['srcIPdist']      = {}
        stats['dstIPdist']      = {}

    #
    #
    def featExtract(self, q):

        proto = ['TCP', 'UDP']
        currentStats = {}

        #just incase timeout occurs
        while True:     
            #listen loop - should put interface in config
            for ts, pkt in pcap.pcap(name='eth1', immediate=True, timeout_ms=60000):
		
		eth = dpkt.ethernet.Ethernet(pkt)

                #non IP packet
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip = eth.data

                #non TCP | UDP datagram
                if ip.data.__class__.__name__ not in proto:
                    continue

                trans = ip.data

                ## add current stats
                currentStats = q.get()

		f.write('gotstats')

                # packet/byte counters
                currentStats['packetcnt'] += 1
                currentStats['bytecnt'] += int(ip.len)

	        # flow counters -- should check if all are present!
                flowStr = self.ip_to_str(ip.src) + self.ip_to_str(ip.dst) + str(trans.sport) + str(trans.dport)
                
		if flowStr not in currentStats['flows']:
                    currentStats['flows'].append(flowStr)
                    currentStats['activeflows'] += 1

                # distributions
                # byte count 
                if ip.len not in currentStats['bytecntdist']:
                    currentStats['bytecntdist'][ip.len] = 0
                currentStats['bytecntdist'][ip.len] += 1

                # src IP
                if self.ip_to_str(ip.src) not in currentStats['srcIPdist']:
                    currentStats['srcIPdist'][self.ip_to_str(ip.src)] = 0
                currentStats['srcIPdist'][self.ip_to_str(ip.src)] += 1

                # dst IP
                if self.ip_to_str(ip.dst) not in currentStats['dstIPdist']:
                    currentStats['dstIPdist'][self.ip_to_str(ip.dst)] = 0
                currentStats['dstIPdist'][self.ip_to_str(ip.dst)] += 1

                # src port
                if trans.sport not in currentStats['srcportdist']:
                    currentStats['srcportdist'][trans.sport] = 0
                currentStats['srcportdist'][trans.sport] += 1

                # dst port
                if trans.dport not in currentStats['dstportdist']:
                    currentStats['dstportdist'][trans.dport] = 0
                currentStats['dstportdist'][trans.dport] += 1

                q.put(currentStats)

    def __init__(self, name, init_config, agent_config):
        super(NetworkStats, self).__init__(name, init_config, agent_config)

        currentStats = {}
        self.resetStats(currentStats)

        self.q = Queue.Queue(1)
        self.q.put(currentStats)

        self.t = threading.Thread(target=self.featExtract, args=(self.q, ))
        self.t.daemon = True
        self.t.start()

    def check(self, instance):
        dimensions = self._set_dimensions(None, instance)

	currentStats = self.q.get()

	#counter
        self.gauge('net_stat.bytecnt', currentStats['bytecnt'],  dimensions)
        self.gauge('net_stat.packetcnt', currentStats['packetcnt'],  dimensions)
        self.gauge('net_stat.activeflows', currentStats['activeflows'],  dimensions)

	#distributions
        self.gauge('net_stat.byte_count_entropy', self.entropy(currentStats['bytecntdist']),  dimensions)
        self.gauge('net_stat.src_port_entropy', self.entropy(currentStats['srcportdist']),  dimensions)
        self.gauge('net_stat.dst_port_entropy', self.entropy(currentStats['dstportdist']),  dimensions)
        self.gauge('net_stat.srcIP_entropy', self.entropy(currentStats['srcIPdist']),  dimensions)
        self.gauge('net_stat.dstIP_entropy', self.entropy(currentStats['dstIPdist']),  dimensions)

        self.resetStats(currentStats)
        self.q.put(currentStats)
        
