/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;
//typedef bit<32> nexthopIP_t;



const bit<32> MAX_PORTS = 128;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<16> TYPE_IPV4         = 0x800;
const bit<16> TYPE_IPV6         = 0x86DD;
const bit<8> TYPE_OSPF          = 89;
const bit<8> TYPE_ICMP          = 1;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
    
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t       ipv4;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
	    TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
	    TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(MAX_PORTS, CounterType.packets_and_bytes) IPCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ARPCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) CPCounter;
    

    ip4Addr_t nexthop;
    bit<32> localcontrol = 0;
    
    
    // register<bit<32>>(1024) myReg;
    
    action writer(ip4Addr_t localIPcontrol) {
	localcontrol = localIPcontrol;
	IPCounter.count((bit<32>) standard_metadata.ingress_port);
        //myReg.write((bit<32>)hdr.ipv4.dstAddr, localcontrol);
    }
   
    
    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
	CPCounter.count((bit<32>) standard_metadata.ingress_port);
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_forward(ip4Addr_t nextHopIP) {
	IPCounter.count((bit<32>) standard_metadata.ingress_port);
        //standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	//hdr.ipv4.srcAddr = nexthopIP;
        //hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	nexthop = nextHopIP;
    }
    
    action arp_lookup(macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
	hdr.ethernet.dstAddr = dstAddr;
    }
	
 
    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size =1024;
        default_action = drop();
    }

    table hellocast {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
	    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table local_ipv4 {
	key = {
	    hdr.ipv4.dstAddr: lpm;
	}
	actions = {
	    writer;
	    drop;
	    NoAction;
	}
	    size = 1024;
	    default_action = NoAction;
    }	

    table arp_lpm {
	key = {
	    nexthop: exact;
	}
	actions = {
	    arp_lookup;
	    send_to_cpu;
	    drop;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction;
    }
	
    apply {
	localcontrol = 0;
	//rules for special IPs 
	local_ipv4.apply();    // check local IP before others
	//bit<32> responseStore = 0x00;
	//myReg.read(responseStore, (bit<32>)hdr.ipv4.dstAddr);
	if (localcontrol == 1) {
	    send_to_cpu();
        }
	if (hdr.ethernet.etherType == TYPE_IPV6) {
	    send_to_cpu();
	}
	else {
        //rules for OSPFs and other IPs	
	    if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0 && standard_metadata.ingress_port == CPU_PORT) {
		CPCounter.count((bit<32>) standard_metadata.egress_port);
		cpu_meta_decap();
		hellocast.apply();
	    }
	    else if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
		ipv4_lpm.apply();
		arp_lpm.apply();			
            }
	    
	    if (hdr.ipv4.isValid() && hdr.ipv4.ttl >0 && hdr.ipv4.protocol == TYPE_OSPF) {
		if (standard_metadata.ingress_port != CPU_PORT) {
		    send_to_cpu();
		}
	    }
	}
	

	//rules for ARPs	
        if (hdr.arp.isValid() && standard_metadata.ingress_port == CPU_PORT){
	    ARPCounter.count((bit<32>) standard_metadata.ingress_port);
	    CPCounter.count((bit<32>) standard_metadata.ingress_port);
	    cpu_meta_decap();
	}
        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
	    ARPCounter.count((bit<32>) standard_metadata.ingress_port);
	    send_to_cpu();
        }
        else if (hdr.arp.isValid()) {
	    ARPCounter.count((bit<32>) standard_metadata.ingress_port);
	    fwd_l2.apply();	    
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
