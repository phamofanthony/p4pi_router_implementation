/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

// Define protocol types
const bit<16> TYPE_ARP         = 0x806;
const bit<16> TYPE_IPv4        = 0x800;
const bit<16> TYPE_CPU_METADATA = 0x080a;

// Header definitions
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header cpu_metadata_t {
    bit<16> origEtherType;
    // Additional metadata fields can be added if needed
}

// Standard metadata and user metadata (if any)
struct metadata {
    // (empty for now)
}

struct headers {
    ethernet_t      ethernet;
    arp_t           arp;
    ipv4_t          ipv4;
    cpu_metadata_t  cpu_metadata;
}

// Parser: extracts Ethernet and then ARP or IPv4 based on etherType
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
            TYPE_ARP:  parse_arp;
            TYPE_IPv4: parse_ipv4;
            default:   accept;
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

// Ingress processing: implement routing logic and special handling for ARP, TTL, and CPU–directed packets.
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // Drop action: simply mark the packet to be dropped.
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // Forward action: update Ethernet header and set egress port.
    action forward(bit<48> newDst, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = newDst;
        standard_metadata.egress_spec = port;
    }
    
    // Send-to-CPU action: set egress to CPU and append metadata.
    action send_to_cpu() {
        // Assume CPU port is reserved (e.g., port 255)
        standard_metadata.egress_spec = 255;
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
    }
    
    // (Optional) A table for IPv4 routing lookup using LPM
    table ipv4_routing {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ethernet.etherType == TYPE_ARP) {
            // All ARP packets are sent to the CPU.
            send_to_cpu();
        } else if (hdr.ethernet.etherType == TYPE_IPv4) {
            // Decrement TTL; if TTL becomes zero, drop the packet.
            if (hdr.ipv4.ttl <= 1) {
                drop();
            } else {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                // If the destination IP is local (for example, in 10.0.0.0/8), forward to CPU.
                if ((hdr.ipv4.dstAddr & 0xff000000) == 0x0a000000) {
                    send_to_cpu();
                } else {
                    // Otherwise, perform routing lookup.
                    ipv4_routing.apply();
                }
            }
        }
    }
}

// Deparser: reassembles the packet (emit headers in order)
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.cpu_metadata);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // do nothing
    }
}

control MyEgress (inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // do nothing
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // do nothing
    }
}

V1Switch(
    MyParser(), 
    MyVerifyChecksum(),
    MyIngress(), 
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()) main;
