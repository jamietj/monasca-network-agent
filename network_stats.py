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

# project
import monasca_agent.collector.checks as checks

log = logging.getLogger(__name__)

class NetworkStats(checks.AgentCheck):

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

        currentStats = {}

        tcpdump     = subprocess.Popen('sudo /usr/sbin/tcpdump -w - -U -i eth1', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        traceStat   = subprocess.Popen('sudo /usr/bin/traceStats -mx', stdin=tcpdump.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	
        for line in iter(traceStat.stdout.readline, ""):

            if line == '':
                continue

            packet = line.split()

            if len(packet)  < 7:
                continue

            currentTime = float(packet[0])

            # initial start time
            if startTime == 0:
                startTime = currentTime

            ## add current stats
            currentStats = q.get()
            # packet/byte counters
            currentStats['packetcnt'] += 1
            currentStats['bytecnt'] += int(packet[6])

            # flow counters -- should check if all are present!
            flowStr = packet[2] + packet[3] + packet[4] + packet[5]
            if flowStr not in currentStats['flows']:
                currentStats['flows'].append(flowStr)
                currentStats['activeflows'] += 1

            # distributions
            # byte count 
            if packet[6] not in currentStats['bytecntdist']:
                currentStats['bytecntdist'][packet[6]] = 0
            currentStats['bytecntdist'][packet[6]] += 1

            # src IP
            if packet[2] not in currentStats['srcIPdist']:
                currentStats['srcIPdist'][packet[2]] = 0
            currentStats['srcIPdist'][packet[2]] += 1

            # dst IP
            if packet[3] not in currentStats['dstIPdist']:
                currentStats['dstIPdist'][packet[3]] = 0
            currentStats['dstIPdist'][packet[3]] += 1

            # src port
            if packet[4] not in currentStats['srcportdist']:
                currentStats['srcportdist'][packet[4]] = 0
            currentStats['srcportdist'][packet[4]] += 1

            # dst port
            if packet[5] not in currentStats['dstportdist']:
                currentStats['dstportdist'][packet[5]] = 0
            currentStats['dstportdist'][packet[5]] += 1

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
        
