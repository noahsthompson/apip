#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header regex_t {
    bit<16> state;
    bit<7> length;
    bit<1> result;
}

header next_chars_t {
    bit <8> nc;
}

struct headers {
    ethernet_t ethernet;
    regex_t regex;
    next_chars_t next_chars;
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
	    16w0x9999: parse_regex;
	    default: accept;
	}
    }
    state parse_regex {
	packet.extract(hdr.regex);
	transition parse_next_chars;
    }
    state parse_next_chars {
	packet.extract(hdr.next_chars);
	transition accept;
    }
    
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bit<16> null = 16w0xFF;

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
