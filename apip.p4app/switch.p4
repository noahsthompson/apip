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
    bit<8> flag;
}

header apip_t {
    bit<16> accAddr;
    bit<16> retAddr;
    bit<32> dstAddr;
}

header verify_t {
    bit <64> fingerprint;
    bit <64> host_sig;
}

header brief_t {
    bit <48> host_id;
    bit <64> bloom;
}

header shutoff_t {
    bit <64> fingerprint;
    bit <64> host_sig;
}

header timeout_t {
    bit <64> fingerprint;
}

struct headers {
    ethernet_t ethernet;
    apip_flag_t apip_flag;
    apip_t apip;
    verify_t verify;
    brief_t brief;
    shutoff_t shutoff;
    timeout_t timeout;
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
            8w0x1: parse_apip;
            8w0x2: parse_brief;
            8w0x3: parse_verify; //verify request
            8w0x4: parse_verify; //verify response
            8w0x5: parse_timeout;
            8w0x6: parse_shutoff; //6 shutoff mal flow
            default: accept;    
        }
    }
    state parse_brief {
        packet.extract(hdr.brief);
        transition accept;
    }

    state parse_apip {
        packet.extract(hdr.apip);
        transition accept;
    }
    
    state parse_verify {
        packet.extract(hdr.verify);
        transition accept;
    }

    state parse_timeout {
        packet.extract(hdr.timeout);
        transition accept;
    }

    state parse_shutoff{
        packet.extract(hdr.shutoff);
        transition accept;
    }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<8>>(256) bloom; 
    bool contains = false;
    bit<64> fingerprint;
    bit<64> signature;

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action calculate_fingerprint() {
        //custom hash
        fingerprint = ( ( (bit<64>) hdr.apip.retAddr) << 32) | (bit<64>) hdr.apip.dstAddr;
    }

    action translate_ret(){
        if(hdr.apip.isValid()){
            //translate
            hdr.apip.retAddr = hdr.apip.retAddr; //would normally translate out
        }
    }

    action untranslate_dst(){
        if(hdr.apip.isValid()){
            //untranslate
            hdr.apip.dstAddr = hdr.apip.dstAddr; //would normally translate in
        }
    }

    action get_signature(){
        // In practical applications this could be done a number of ways, for now we use a dummy val
        signature = 64w0x0;
    }

    action set_nhop(bit<32> nhop_apip, bit<9> port) {
        meta.ingress_metadata.nhop_apip = nhop_apip;
        standard_metadata.egress_spec = port;
    }

    action set_mac(bit<48> mac) {
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac;
    }

    action fwd_delegate(bit<48> dmac, bit<9> port){
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
    }

    action send_verification_request(){
        hdr.apip.setInvalid();
        hdr.verify.setValid();
        hdr.apip_flag.flag = 8w0x3;

        hdr.verify.fingerprint = fingerprint;
        hdr.verify.host_sig = signature;
        
        standard_metadata.egress_spec = 3; //hardcoded for now, extract from accAddr or use table
        hdr.ethernet.dstAddr = (bit<48>) hdr.apip.accAddr;
    }

    action check_bloom(){
        bit<32> ix1;
        bit<32> ix2;
        bit<32> ix3;

        bit<8> val1;
        bit<8> val2;
        bit<8> val3;

        hash(ix1, HashAlgorithm.crc16, 32w0x0, {fingerprint}, 32w0xFF);
        hash(ix2, HashAlgorithm.csum16, 32w0x0, {fingerprint}, 32w0xFF);
        hash(ix3, HashAlgorithm.identity, 32w0x0, {fingerprint}, 32w0xFF);

        bloom.read(val1, ix1);
        bloom.read(val2, ix2);
        bloom.read(val3, ix3);

        contains = ((val1 > 0) && (val2 > 0)) && (val3 > 0);
    }

    action update_bloom(bit<1> polarity) {
        bit<32> ix1;
        bit<32> ix2;
        bit<32> ix3;

        bit<8> val1;
        bit<8> val2;
        bit<8> val3;

        hash(ix1, HashAlgorithm.crc16, 32w0x0, {fingerprint}, 32w0xFF);
        hash(ix2, HashAlgorithm.csum16, 32w0x0, {fingerprint}, 32w0xFF);
        hash(ix3, HashAlgorithm.identity, 32w0x0, {fingerprint}, 32w0xFF);

        bloom.read(val1, ix1);
        bloom.read(val2, ix2);
        bloom.read(val3, ix3);

        if(polarity == 1){
            val1 = val1 + 1;
            val2 = val2 + 1;
            val3 = val3 + 1;
        }
        else {
            val1 = val1 - 1;
            val2 = val2 - 1;
            val3 = val3 - 1;
        }

        bloom.write(ix1, val1);
        bloom.write(ix2, val2);
        bloom.write(ix3, val3);
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
            set_mac;
            _drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_apip: exact;
        }
        size = 512;
        default_action = _drop();
    }

    table brief {
        actions = {
            _drop;
            fwd_delegate;
            NoAction;
        }
        key = {
            hdr.brief.host_id : exact;
        }
        size = 1024;
        default_action = _drop();
    }

    table shutoff {
        actions = {
            _drop;
            fwd_delegate;
            NoAction;
        }
        key = {
            hdr.brief.host_id : exact;
        }
        size = 1024;
        default_action = _drop();
    }

    apply {
        if (hdr.apip.isValid()) { // normal apip message
            calculate_fingerprint();
            check_bloom();
            if(contains){ // either forward
                translate_ret();
                untranslate_dst();
                apip_lpm.apply();
                forward.apply();
            }
            else{ // or request a verification
                get_signature();
                send_verification_request();
            }
        }
        else if (hdr.verify.isValid()){ //receiving verify request
            fingerprint = hdr.verify.fingerprint;
            update_bloom(1);
        }
        else if (hdr.brief.isValid()){ //forwarding a briefing
            brief.apply();
        }
        else if (hdr.timeout.isValid()){ //timeout a flow
            fingerprint = hdr.timeout.fingerprint;
            update_bloom(0);
        }
        else if (hdr.shutoff.isValid()){ //shutoff a flow
            fingerprint = hdr.shutoff.fingerprint;
            update_bloom(0);
            shutoff.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    table send_frame {
        actions = {
            rewrite_mac;
            _drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = _drop();
    }
    apply {
        //Range 1-3 are forwarded (4 and 5 are never sent)
        if ((hdr.apip_flag.flag >= 1) && (hdr.apip_flag.flag <= 3)) {
          send_frame.apply();
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { 
        packet.emit(hdr.ethernet);
        packet.emit(hdr.apip_flag);

        packet.emit(hdr.apip);
        packet.emit(hdr.verify);
        packet.emit(hdr.brief);
        packet.emit(hdr.shutoff);
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
