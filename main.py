from p4app import P4Mininet
from controller import MacLearningController
from mininet.topo import Topo

from scapy.all import sendp, IP, Ether
from async_sniff import sniff
import pwospfpackets

import sys
import time




#create a custom topology
print "Setting up a switch where s2<->s3<->s4, with each attached to the respective host"

N = 4; #number of switches

class customTopo(Topo):     ##here, 3 switches, each switch, 1 controller + hosts
	def __init__(self):
		Topo.__init__(self)
		
		switches = []
		sw2=self.addSwitch('s2')
		sw3=self.addSwitch('s3')
		sw4=self.addSwitch('s4')
		switches.append(sw2)
		switches.append(sw3)
		switches.append(sw4)		
		
		self.addHost('h2', ip="10.0.0.2", mac="00:00:00:00:00:02")
		self.addHost('h3', ip="10.0.0.3", mac="00:00:00:00:00:03")
		self.addHost('h4', ip="10.0.0.4", mac="00:00:00:00:00:04")

		self.addHost('cp2', ip="10.0.1.2", mac="00:00:00:00:01:02")
		self.addHost('cp3', ip="10.0.1.3", mac="00:00:00:00:01:03")
		self.addHost('cp4', ip="10.0.1.4", mac="00:00:00:00:01:04")
		
		self.addLink('h2','s2',port1=1, port2=2)
		self.addLink('h3','s3',port1=1, port2=2)
		self.addLink('h4','s4',port1=1, port2=2)

		self.addLink('cp2','s2',port1=1, port2=1)
		self.addLink('cp3','s3',port1=1, port2=1)
		self.addLink('cp4','s4',port1=1, port2=1)

		self.addLink('s2','s3', port1=3, port2=3)
		self.addLink('s3','s4', port1=4, port2=3)
		#self.addLink('s4','s2', port1=4, port2=3)


#innitiate the topology
topo = customTopo()
net = P4Mininet(program='l2switch.p4', topo=topo, enable_debugger=True, auto_arp=False)
net.start()

#pingtester
def pingtester():
	N=4;
	for i in range(N,1,-1):
		hs = net.get('h%d' % i)
		for j in range(2,N+1):
		        #hd = net.get('h%d' % j)
			#print hs
			#print hd
		        print hs.cmd('ping -c1 -w1 10.0.0.%d' %j)
			print('just did %d to %d' %(i,j))
			#print hs.cmd('netstat -nr')
		


#add forwarding to hosts
for i in range(2, N+1):
	sw = net.get('s%d' % i) 
	sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'nextHopIP': "10.0.0.%d" % i})

	sw.insertTableEntry(table_name='MyIngress.local_ipv4',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.1.%d" % i, 32]},
                        action_name='MyIngress.writer',
                        action_params={'localIPcontrol': 1})

'''
	sw.insertTableEntry(table_name='MyIngress.local_ipv4',
                        match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5", 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'dstAddr': '00:00:00:00:01:%02x' % i,
                                          'port': 1})
'''

for i in range(2, N+1): #check tables
	sw = net.get('s%d' % i) 
	sw.printTableEntries() 
#pingtester() #check
#time.sleep(1)


icmpset=[net.get('cp2').IP(), net.get('cp3').IP(), net.get('cp4').IP()]


#start controller
for i in range(N, 1, -1):
	# Add a mcast group for all ports (except for the CPU port)
	bcast_mgid = 1
	bcast_mgidhello = 2
	sw = net.get('s%d'%i)
	hw = net.get('h%d'%i)
	cpw = net.get('cp%d'%i)
	sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
	sw.addMulticastGroup(mgid=bcast_mgidhello, ports=range(3, N+1))

	# Send MAC bcast packets to the bcast multicast group
	sw.insertTableEntry(table_name='MyIngress.fwd_l2',
		match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
		action_name='MyIngress.set_mgid',
		action_params={'mgid': bcast_mgid})


	sw.insertTableEntry(table_name='MyIngress.hellocast',
		match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
		action_name='MyIngress.set_mgid',
		action_params={'mgid': bcast_mgidhello})


	data = {} 
	temp ='cpu%d'%i 
	# Start the MAC learning controller
	print 'starting ', temp
	data[temp] = MacLearningController(sw,hw,cpw,icmpset)
	data[temp].daemon = True
	data[temp].start()
	# These table entries were added by the CPU:
	sw.printTableEntries()

time.sleep(1)
pingtester() #check


time.sleep(18)
pingtester() #check

#periodic ping tests, and packet countring
while (True):
	time.sleep(2)
	pingtester() #check


	for j in range(2,N+1):
		sw = net.get('s%d' % i)  
    		packet_count, byte_count = sw.readCounter('IPCounter',2)
		print ('IP packet count for host->switch %d is %d'%(j,packet_count))

		packet_count, byte_count = sw.readCounter('ARPCounter',1)
	        print ('ARP packet count into switch %d is %d'%(j,packet_count))

		packet_count, byte_count = sw.readCounter('CPCounter',1)
		print ('Control plane packet count for switch %d is %d'%(j,packet_count))
	time.sleep(4)
