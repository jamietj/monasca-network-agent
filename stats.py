from pypcap import pcap
import dpkt
import socket
import datetime

x = pcap()
x.pcap_create( 'eth1' )
x.pcap_set_promisc( True )
x.pcap_activate()


def ip_to_str(ip):
    return socket.inet_ntop(socket.AF_INET, ip)

# time TCP|UDP src_addr dst_addr src_port dst_port ip_len
def pcap_callback(pkt, ts):
    # do stuff with packet
    eth = dpkt.ethernet.Ethernet(pkt)

    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
    	print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
	return 

    ip = eth.data
    proto = ip.data.__class__.__name__

    if proto != "UDP" or proto != "TCP":
	print 'Non UDP or TCP datagram not supported ' + proto

        
    #print(str(datetime.datetime.utcfromtimestamp(ts))),
    print(ts),
    print(proto),
    print(ip_to_str(ip.src)),
    print(ip_to_str(ip.dst)),

    trans = ip.data

    print(trans.dport),
    print(trans.sport),
    print(ip.len),    

    print " "

x.pcap_set_callback(pcap_callback)
x.pcap_loop()

