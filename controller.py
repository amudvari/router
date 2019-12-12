from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from dijkstra import dijkstra
import time
import pwospfpackets
import socket
from mininet.topo import Topo

    

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
OSPF_NUM     = 0x0089

class MacLearningController(Thread):     
    def __init__(self, sw, ctrl_port=1,  start_wait=0.3):
#hw, cpw, 
        super(MacLearningController, self).__init__()
        self.sw = sw
	print('################')
	print('###################')
	print (self.sw.name)
	time.sleep(4)
	if self.sw.name == 'sw2':
		print("#####************")
		self.hwIP = '10.0.0.2'
		self.cpwIP ='10.0.1.2'
		self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.2", 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'nextHopIP': "10.0.0.2"})

		self.sw.insertTableEntry(table_name='MyIngress.local_ipv4',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.1.2", 32]},
                        action_name='MyIngress.writer',
                        action_params={'localIPcontrol': 1})
	if self.sw.name == 'sw3':
		self.hwIP = '10.0.0.3'
		self.cpwIP ='10.0.1.3'
		self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.3", 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'nextHopIP': "10.0.0.3"})

		self.sw.insertTableEntry(table_name='MyIngress.local_ipv4',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.1.3", 32]},
                        action_name='MyIngress.writer',
                        action_params={'localIPcontrol': 1})


        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
	self.arp_table = {}


	self.helloexpire = 0
	self.neighborsPort = {}

	self.routers = {}
	self.seqStore = {}
	self.nextHop = {}
	self.genSeq = 100
	self.startTime = time.time()
	self.Track = 1

	self.icmptimeout = 5
	self.icmptrigger = {}
	self.icmptimer = {}
	self.ICMPseq = 500
	self.Track2 = 0

        self.stop_event = Event()
	print "######thread for", sw, " running#########"





    def addMacAddr(self, mac, ipsrc, port):       ##MAC based on IP, update MAC address
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return
	#if ipsrc in self.arp_table: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})

	self.sw.insertTableEntry(table_name='MyIngress.arp_lpm',
        	match_fields={'nexthop': [ipsrc]},
        	action_name='MyIngress.arp_lookup',
        	action_params={'dstAddr': [mac],
				'port': port})

        self.port_for_mac[mac] = port
	self.arp_table[ipsrc] = [mac],port,time.time()
	
    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[ARP].psrc, pkt[CPUMetadata].srcPort)       
	self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[ARP].psrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def run(self):
	sniffer = Thread(target = sniff, kwargs={'iface':self.iface, 'prn':self.handlePkt, 'stop_event':self.stop_event})
	clocker = Thread(target = self.clockEvents)
	sniffer.start()
	clocker.start()

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)






   
    def handlePkt(self, pkt):           ##handle incoming packets to controller
        
	assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return
 	
        if ARP in pkt:
	    #print "arp"
	    if pkt[ARP].op == ARP_OP_REQ:
	        self.handleArpRequest(pkt)
	    elif pkt[ARP].op == ARP_OP_REPLY:
	        self.handleArpReply(pkt)

	elif IP in pkt:
	    #print "other"
	    #print ('received OSPF proto is %d'%pkt[pwospfpackets.OSPF_Hdr].type)   
	    if pwospfpackets.OSPF_Hdr in pkt:     
	        if pkt[pwospfpackets.OSPF_Hdr].type == 1:
		    self.rcvHello(pkt)
	        elif pkt[pwospfpackets.OSPF_Hdr].type == 4:
		    self.rcvLSU(pkt)
	
	if IP in pkt: 
	    validation = self.validateIP(pkt)
	    if validation == 0:
		print pkt[IP].dst
		print ('invalid')

	#if ICMP in pkt:
		#self.receivePing(pkt)


    def validateIP(self, *args, **kwargs):      #validate IP address
	pkt = args[0]
	addr = pkt[IP].dst
	div = addr.split(".")
	if len(div) != 4:
		return 0
	for sections in div:
	 if int(sections) < 0 or int(sections) > 255:
		return 0
	return 1


    def send(self, *args, **override_kwargs):      #handle sent message
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)
  



 
    def clockEvents(self, *args, **kwargs):    ##handles periodic events like sending hello message, send periodic LSU message (or trigger if hello not sent for a while), and update ARP table

	hellotimer = time.time()
	helloint = 5
	LSUtimer = time.time()
	LSUint = 10
	arpTimeout = 10000
	time.sleep(2);
	#self.sendPing();
	print("in clocker")

	while (True):  
		#print self.port_for_mac     	
		if ((time.time()-hellotimer) > helloint):
			hellotimer = time.time()
			self.sendHello()
		
		for neighborID in self.neighborsPort:
			portntime = self.neighborsPort[neighborID] #time is second entry
			if ( (time.time()-portntime[1]) > helloint*3):
				self.sendLSU()
				LSUtimer = time.time()
		if ( time.time() - LSUtimer > LSUint ):
			self.sendLSU()
			LSUtimer = time.time() 
		
		for arpEntry in self.arp_table:
			entry = self.arp_table[arpEntry]
			entryTime = entry[2]
			if ((time.time() - entryTime) > arpTimeout) :
				del self.arp_table[arpEntry]

		if self.Track2 == 1:
			time.sleep(5)
			#self.sendPing()    #tries local ping
			self.Track2 = 0
 
		time.sleep(1)








    def sendHello(self, *args, **kwargs):      #send hello message
	A=(Ether(dst='ff:ff:ff:ff:ff:ff')/
	CPUMetadata(fromCpu=1, origEtherType=0x800, srcPort=1)/
	IP(src=self.hwIP)/
	pwospfpackets.OSPF_Hdr(src=self.hwIP)/pwospfpackets.OSPF_Hello(hellointerval=10, prio=1, deadinterval=40 ))
	#print("Hello sent")
	self.send(A)

    def rcvHello(self, *args, **kwargs):     #handle received Hello message
	pkt = args[0]
	#print("Hello received")
	neighborID = pkt[pwospfpackets.OSPF_Hdr].src
	if neighborID not in self.neighborsPort: 
		self.neighborsPort[neighborID] = [pkt[CPUMetadata].srcPort, time.time()] 
		self.sendLSU();
	else:
		self.neighborsPort[neighborID] = [pkt[CPUMetadata].srcPort, time.time()]






	
    def sendLSU(self, *args, **kwargs):    #send LSU packets
	#print("sending LSU")	
	arg = []
	for neighborID in self.neighborsPort:
		arg.append(pwospfpackets.OSPF_Link(type =3, metric =10, data=self.hwIP, id = neighborID))	
	#print(self.neighborsPort)
	self.genSeq = self.genSeq+1;
	#print("LSU sent")
	A= (Ether(dst='ff:ff:ff:ff:ff:ff')/
	CPUMetadata(fromCpu=1, origEtherType=0x800, srcPort=1)/
	IP(src=self.hwIP, ttl=8)/
	pwospfpackets.OSPF_Hdr(src=self.hwIP)/
	pwospfpackets.OSPF_LSUpd(lsalist=pwospfpackets.OSPF_Router_LSA(seq=self.genSeq, age=10, adrouter=self.cpwIP, linklist=arg, id=self.hwIP )  ) )

	self.send(A)


    def rcvLSU(self, *args, **kwargs):      ##handle received OSPF packet
	pkt = args[0]
	#print("LSU received")
	#print pkt[pwospfpackets.OSPF_Router_LSA].id
	#print self.hwIP
	origin = pkt[pwospfpackets.OSPF_Router_LSA].id
	nodelist = pkt[pwospfpackets.OSPF_Router_LSA].linklist
	nodeseq = pkt[pwospfpackets.OSPF_Router_LSA].seq
	nodeage = pkt[pwospfpackets.OSPF_Router_LSA].age
	#print (len(nodelist))

	newstatus = 1	
	if origin not in self.seqStore:
		self.seqStore[origin] = nodeseq
		self.updateTable(origin, nodelist, newstatus, pkt)	
	elif (origin in self.seqStore) and (nodeseq > self.seqStore[origin]):
		newstatus = 0 	
		self.updateTable(origin, nodelist, newstatus, pkt)

		
    def updateTable(self, *args, **kwargs):     ##update the routing table with the help of dijkstra
	origin = args[0]
	nodelist = args[1]
	newstatus = args[2]

	if newstatus == 0:
		del self.routers[origin]

	OriginRouters = []	
	for entry in nodelist:
		OriginRouters.append(entry.id)	

	self.routers[origin] = OriginRouters
	#print self.routers
	

	if newstatus == 0:
		del self.routers[origin]
		self.routers[origin] = OriginRouters
	
	routerList = list(self.routers.keys())	
	
	if self.hwIP not in routerList:
		self.fwdLSU(args[3])
	else: 
		currentRouter = routerList.index(self.hwIP)

		#print("running dijkstra")
		self.nextHop = dijkstra(self.routers, currentRouter)

	
		#print(routerList, currentRouter)
		#print(self.nextHop)

		if (time.time()-self.startTime > 18 and self.Track==1):
			self.changeRules(routerList)	

		self.fwdLSU(args[3])


    def changeRules(self, *args, **kwargs):   ##update tables after running dijkstra	
	routerList = args[0]
	for j in range(len(routerList)):
		if routerList[j] in self.nextHop:
			self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
		                match_fields={'hdr.ipv4.dstAddr': [routerList[j], 32]},
		                action_name='MyIngress.ipv4_forward',
		                action_params={'nextHopIP': self.nextHop[routerList[j]] })
	print (self.sw.printTableEntries())
	print (self.arp_table)
	#print (self.port_for_mac)
	self.Track2=1
	self.Track=0


    def fwdLSU(self, *args, **kwargs):    
	pkt=args[0]	
	self.send(pkt)




'''
	if self.hwIP == '10.0.0.2' :
		arg =[pwospfpackets.OSPF_Link(type=3, metric=10, data=self.hwIP, id='10.0.0.3', toscount=0)] 
	
	if self.hwIP == '10.0.0.3' :
		arg =[pwospfpackets.OSPF_Link(type=3, metric=10, data=self.hwIP, id='10.0.0.2', toscount=0), pwospfpackets.OSPF_Link(type=3, metric=10, data=self.hwIP, id='10.0.0.4', toscount=0)] 

	if self.hwIP == '10.0.0.4' :
		arg =[pwospfpackets.OSPF_Link(type=3, metric=10, data=self.hwIP, id='10.0.0.3', toscount=0)] 
'''
	
