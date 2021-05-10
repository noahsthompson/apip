#include <core.p4>
#include <v1model.p4>

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

header verif_info_t {
    bit <64> fingerprint;
    bit <64> msg_auth;
}

struct headers {
    ethernet_t ethernet;
    apip_flag_t apip_flag;
    apip_t apip;
    verif_info_t verif_info;

} 

struct metadata {
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
            4w0x3: parse_verif_info;
            4w0x4: parse_verif_info;
            default: accept;    
        }
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

    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action goto(bit<16> state) {
        hdr.regex.state = state;
    }
    action is_final() {
        hdr.regex.result = 1;
    }
    action is_not_final() {
        hdr.regex.result = 0;
    }

    table transitions {
	actions = {
	    goto;
	    _drop;
	    NoAction;
	}
	key = {
	    hdr.regex.state: exact;
	    hdr.next_chars.nc: exact;
	}
	size = 1024;
	default_action = NoAction;
    }
    table final {
        actions = {
            is_final;
            is_not_final;
            NoAction;
        }
        key = {
            hdr.regex.state: exact;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
	hdr.regex.length = hdr.regex.length - 1;

	transitions.apply();
    	
	if(hdr.regex.length == 0){
	    final.apply();
	}
	
	standard_metadata.egress_spec = standard_metadata.ingress_port;
	
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
