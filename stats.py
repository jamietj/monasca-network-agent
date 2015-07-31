import pcap
import dpkt
import socket
import datetime

proto = ['UDP', 'TCP']

x = pcap.pcap(name='eth1',immediate=True, timeout_ms=10000)

def ip_to_str(ip):
	return socket.inet_ntop(socket.AF_INET, ip)

# time TCP|UDP src_addr dst_addr src_port dst_port ip_len
def pcap_callback(ts, pkt):
	# do stuff with packet
	eth = dpkt.ethernet.Ethernet(pkt)

	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
    		print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
		return 

   	ip = eth.data

    	if ip.data.__class__.__name__ not in proto:
		print 'Non UDP or TCP datagram not supported ' + ip.data.__class__.__name__
		return
        
    	print(ts),
    	print(ip.data.__class__.__name__),
    	print(ip_to_str(ip.src)),
    	print(ip_to_str(ip.dst)),

    	trans = ip.data

    	print(trans.dport),
    	print(trans.sport),
    	print(ip.len),    

    	print " "

while True:
	x.loop(0, pcap_callback)
