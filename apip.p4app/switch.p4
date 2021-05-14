#include <core.p4>
#include <v1model.p4>

struct ingress_metadata_t {
    bit<32> nhop_apip;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header apip_flag_t {
    bit<4> flag;
}

header apip_t {
    bit<16> accAddr;
    bit<16> retAddr;
    bit<32> dstAddr;
}

header verify_t {
    bit <64> fingerprint;
    bit <64> msg_auth;
}

header brief_t {
    bit <48> host_id;
    bit <64> bloom;
}

struct headers {
    ethernet_t ethernet;
    apip_flag_t apip_flag;
    apip_t apip;
    verify_t verify;
    brief_t brief;

} 

struct metadata {
    ingress_metadata_t   ingress_metadata;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
	    transition parse_ethernet;
    }
    state parse_ethernet {
    	packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            16w0x87DD: parse_apip_flag;
            default: accept;
        }
    }
    state parse_apip_flag {
        packet.extract(hdr.apip_flag);
        transition select (hdr.apip_flag.flag) {
            4w0x1: parse_apip;
            4w0x2: parse_brief
            4w0x3: parse_verif_info;
            4w0x4: parse_verif_info;
            default: accept;    
        }
    }
    state parse_brief {
        packet.extract(hdr.brief);
        transition: accept;
    }

    state parse_apip {
        packet.extract(hdr.apip);
        transition: accept;

    }
    state parse_verif_info{
        packet.extract(hdr.verif_info);
        transition: accept;

    }

}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<8>>(256) bloom; 
    bit<1> contains;
    contains = 0;

    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    action check_bloom(){
        bit<7> ix1;
        bit<7> ix2;
        bit<7> ix3;

        bit<8> val1;
        bit<8> val2;
        bit<8> val3;

        hash(ix1, HashAlgorithm.crc16, 32w0x0, {hdr.apip.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);
        hash(ix2, HashAlgorithm.csum16, 32w0x0, {hdr.ipv4.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);
        hash(ix3, HashAlgorithm.identity, 32w0x0, {hdr.ipv4.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);

        bloom.read(val1, ix1);
        bloom.read(val2, ix2);
        bloom.read(val3, ix3);

        contains = (val1 && val2) && val3
    }

    action update_bloom(bit<1> polarity) {
        bit<7> ix1;
        bit<7> ix2;
        bit<7> ix3;

        bit<8> val1;
        bit<8> val2;
        bit<8> val3;

        hash(ix1, HashAlgorithm.crc16, 32w0x0, {hdr.apip.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);
        hash(ix2, HashAlgorithm.csum16, 32w0x0, {hdr.ipv4.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);
        hash(ix3, HashAlgorithm.identity, 32w0x0, {hdr.ipv4.retAddr, hdr.ipv4.dstAddr}, 32w0xFF);

        bloom.read(val1, ix1);
        bloom.read(val2, ix2);
        bloom.read(val3, ix3);

        if(polarity = 1){
            val1 = val1 + 1;
            val2 = val2 + 1;
            val3 = val3 + 1;
        }
        else {
            val1 = val1 - 1;
            val2 = val2 - 1;
            val3 = val3 - 1;
        }
        

        bloom.write(val1, ix1);
        bloom.write(val2, ix2);
        bloom.write(val3, ix3);
    }

    
    table apip_lpm {
        actions = {
            _drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.apip.dstAddr: lpm;
        }
        size = 1024;
        default_action = _drop();
    }
    table forward {
        actions = {
            set_dmac;
            _drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = _drop();
    }

    apply {

    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { 
        packet.emit(hdr.ethernet);
	packet.emit(hdr.regex);
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
