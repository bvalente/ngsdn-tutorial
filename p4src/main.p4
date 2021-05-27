/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 //VXLAN credit to https://github.com/P4-Research/p4-demos


#include <core.p4>
#include <v1model.p4>

// CPU_PORT specifies the P4 port number associated to controller packet-in and
// packet-out. All packets forwarded via this port will be delivered to the
// controller as P4Runtime PacketIn messages. Similarly, PacketOut messages from
// the controller will be seen by the P4 pipeline as coming from the CPU_PORT.
#define CPU_PORT 255

// CPU_CLONE_SESSION_ID specifies the mirroring session for packets to be cloned
// to the CPU port. Packets associated with this session ID will be cloned to
// the CPU_PORT as well as being transmitted via their egress port (set by the
// bridging/routing/acl table). For cloning to work, the P4Runtime controller
// needs first to insert a CloneSessionEntry that maps this session ID to the
// CPU_PORT.
#define CPU_CLONE_SESSION_ID 99

// Maximum number of hops supported when using SRv6.
// Required for Exercise 7.
#define SRV6_MAX_HOPS 4

// Constants for VXLAN packet encapsulation
#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define VXLAN_HDR_SIZE 8
#define IP_VERSION_4 4
#define IPV4_MIN_IHL 5

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;

const bit<8> IP_PROTO_ICMP   = 1;
const bit<8> IP_PROTO_TCP    = 6;
const bit<8> IP_PROTO_UDP    = 17;
const bit<8> IP_PROTO_SRV6   = 43;
const bit<8> IP_PROTO_ICMPV6 = 58;

const bit<16> UDP_PORT_VXLAN = 4789;

const bit<16> ARP_REQUEST     = 1;
const bit<16> ARP_REPLY       = 2;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;

const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;

const bit<32> NDP_FLAG_ROUTER    = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE  = 0x20000000;


//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------

header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header srv6h_t {
    bit<8>   next_hdr;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segment_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header srv6_list_t {
    bit<128>  segment_id;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

header arp_t {
    bit<16>   hwType16;
    bit<16>   protoType;
    bit<8>    hwAddrLen;
    bit<8>    protoAddrLen;
    bit<16>   opcode;
    bit<48>   hwSrcAddr;
    bit<32>   protoSrcAddr;
    bit<48>   hwDstAddr;
    bit<32>   protoDstAddr;
}

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved_2;
}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
@controller_header("packet_in")
header cpu_in_header_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
@controller_header("packet_out")
header cpu_out_header_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}

struct parsed_headers_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t cpu_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    srv6h_t srv6h;
    srv6_list_t[SRV6_MAX_HOPS] srv6_list;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
    arp_t arp;

    vxlan_t vxlan;
    ethernet_t inner_ethernet;
    ipv4_t inner_ipv4;
}

struct local_metadata_t {
    l4_port_t   l4_src_port;
    l4_port_t   l4_dst_port;
    bool        is_multicast;
    ipv6_addr_t next_srv6_sid;
    bit<8>      ip_proto;
    bit<8>      icmp_type;
    bit<16>     arp_op;
    bit<24>     vxlan_vni;
    bit<32>     nexthop;
    bit<32>     vtepIP;
}


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.cpu_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        local_metadata.arp_op = hdr.arp.opcode;
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.udp.dst_port) {
            UDP_PORT_VXLAN: parse_vxlan;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type){
            ETHERTYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            default: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using
        // bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }
}


control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    // Not used here. We assume all packets have valid checksum, if not, we let
    // the end hosts detect errors.
    apply { /* EMPTY */ }
}


control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    // Drop action shared by many tables.
    action drop() {
        mark_to_drop(standard_metadata);
    }


    // *** L2 BRIDGING
    //
    // Here we define tables to forward packets based on their Ethernet
    // destination address. There are two types of L2 entries that we
    // need to support:
    //
    // 1. Unicast entries: which will be filled in by the control plane when the
    //    location (port) of new hosts is learned.
    // 2. Broadcast/multicast entries: used replicate NDP Neighbor Solicitation
    //    (NS) messages to all host-facing ports;
    //
    // For (2), unlike ARP messages in IPv4 which are broadcasted to Ethernet
    // destination address FF:FF:FF:FF:FF:FF, NDP messages are sent to special
    // Ethernet addresses specified by RFC2464. These addresses are prefixed
    // with 33:33 and the last four octets are the last four octets of the IPv6
    // destination multicast address. The most straightforward way of matching
    // on such IPv6 broadcast/multicast packets, without digging in the details
    // of RFC2464, is to use a ternary match on 33:33:**:**:**:**, where * means
    // "don't care".
    //
    // For this reason, our solution defines two tables. One that matches in an
    // exact fashion (easier to scale on switch ASIC memory) and one that uses
    // ternary matching (which requires more expensive TCAM memories, usually
    // much smaller).

    // --- l2_exact_table (for unicast entries) --------------------------------

    action set_egress_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        // The @name annotation is used here to provide a name to this table
        // counter, as it will be needed by the compiler to generate the
        // corresponding P4Info entity.
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        // gid will be used by the Packet Replication Engine (PRE) in the
        // Traffic Manager--located right after the ingress pipeline, to
        // replicate a packet to multiple egress ports, specified by the control
        // plane by means of P4Runtime MulticastGroupEntry messages.
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // MY EXERCISE

    // VXLAN

    // VXLAN Ingress Upstream

    action vxlan_decap() {
        // set outter headers as invalid
        // hdr.ethernet.setInvalid();
        // hdr.ipv4.setInvalid();
        // hdr.udp.setInvalid();
        // hdr.vxlan.setInvalid();

        // merge headers for L2 routing
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.udp.setInvalid();
        hdr.vxlan.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    table vxlan_term_table {
        key = {
            hdr.inner_ethernet.dst_addr: exact;
        }

        actions = {
            @defaultonly NoAction;
            vxlan_decap();
        }
    }

    // same as set_egress_port
    // action forward(bit<9> port) {
    //     standard_metadata.egress_spec = port;
    // }

    // same as l2_exact_table
    // table t_forward_l2 {
    //     key = {
    //         hdr.inner_ethernet.dst_addr : exact;
    //     }

    //     actions = {
    //         forward;
    //     }
    // }

    // VXLAN Egress Upstream

    // No Action

    // VXLAN Ingress Downstream

    action set_vni(bit<24> vni) {
        local_metadata.vxlan_vni = vni;
    }


    table vxlan_segment_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            @defaultonly NoAction;
            set_vni;
        }
    }

    action set_ipv4_nexthop(bit<32> nexthop) {
        local_metadata.nexthop = nexthop;
    }

    table vxlan_nexthop_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_ipv4_nexthop;
        }
    }

    action set_vtep_ip(bit<32> vtep_ip) {
        local_metadata.vtepIP = vtep_ip;
    }

    table vtep_table {
        key = {
            hdr.ethernet.src_addr: exact;
        }
        actions = {
            set_vtep_ip;
        }
    }

    // same as set_egress_port
    // action route(bit<9> port) {
    //     standard_metadata.egress_spec = port;
    // }

    // mix of l2_exact_table and routing_v4_table
    // table vxlan_routing {
    //     key = {
    //         local_metadata.nexthop: exact;
    //     }
    //     actions = {
    //         route;
    //     }
    // }

    // VXLAN Egress Downstream

    // action rewrite_macs(bit<48> smac, bit<48> dmac) {
    //     hdr.ethernet.src_addr = smac;
    //     hdr.ethernet.dst_addr = dmac;
    // }

    // table t_send_frame {
    //     key = {
    //         hdr.ipv4.dst_addr : exact;
    //     }
    //     actions = {
    //         rewrite_macs;
    //     }
    // }

    action vxlan_encap() {

        hdr.inner_ethernet = hdr.ethernet;
        hdr.inner_ipv4 = hdr.ipv4;

        hdr.ethernet.setValid();

        hdr.ipv4.setValid();
        hdr.ipv4.version = IP_VERSION_4;
        hdr.ipv4.ihl = IPV4_MIN_IHL;
        // hdr.ipv4.diffserv = 0;
        hdr.ipv4.dscp = 0;
        hdr.ipv4.ecn = 0;
        hdr.ipv4.total_len = hdr.ipv4.total_len
                            + (ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.ipv4.identification = 0x1513; /* From NGIC */
        hdr.ipv4.flags = 0;
        hdr.ipv4.frag_offset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = IP_PROTO_UDP;
        hdr.ipv4.dst_addr = local_metadata.nexthop;
        hdr.ipv4.src_addr = local_metadata.vtepIP;
        hdr.ipv4.hdr_checksum = 0;

        hdr.udp.setValid();
        // The VTEP calculates the source port by performing the hash of the inner Ethernet frame's header.
        hash(hdr.udp.src_port, HashAlgorithm.crc16, (bit<13>)0, { hdr.inner_ethernet }, (bit<32>)65536);
        hdr.udp.dst_port = UDP_PORT_VXLAN;
        hdr.udp.len = hdr.ipv4.total_len + (UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.reserved = 0;
        hdr.vxlan.reserved_2 = 0;
        hdr.vxlan.flags = 0;
        hdr.vxlan.vni = local_metadata.vxlan_vni;

    }

    // L2

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector_l2;

    table l2_exact_table_ecmp {
        key = {
            hdr.ethernet.dst_addr: exact;
            hdr.ipv4.dst_addr: selector;
            hdr.ipv4.src_addr: selector;
            local_metadata.l4_src_port: selector;
            local_metadata.l4_dst_port: selector;
            //hope this works
            hdr.ipv4.identification: selector;
            hdr.ipv4.total_len: selector;
        }
        actions = {
            set_egress_port;
        }
        implementation = ecmp_selector_l2;
        @name("l2_exact_table_ecmp_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    action arp_request_to_reply(mac_addr_t target_mac) {
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = target_mac;
        hdr.arp.opcode = ARP_REPLY;
        hdr.arp.hwDstAddr = hdr.arp.hwSrcAddr;
        hdr.arp.hwSrcAddr = target_mac;
        bit<32> protoDstAddr = hdr.arp.protoDstAddr;
        hdr.arp.protoDstAddr = hdr.arp.protoSrcAddr;
        hdr.arp.protoSrcAddr = protoDstAddr;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_reply_table {
        key = {
            hdr.arp.protoDstAddr: exact;
        }
        actions = {
            arp_request_to_reply;
        }
        @name("arp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector_v4;

    // routing_v4_table
    action set_next_hop_v4(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table routing_v4_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
            hdr.ipv4.dst_addr: selector;
            hdr.ipv4.src_addr: selector;
            //hdr.ipv4.flow_label: selector;
            //hdr.ipv4.next_hdr: selector;
            local_metadata.l4_src_port: selector;
            local_metadata.l4_dst_port: selector;
        }
        actions = {
            set_next_hop_v4;
        }
        implementation = ecmp_selector_v4;
        @name("routing_v4_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    // *** DONE EXERCISE 5 (IPV6 ROUTING)
    //
    // 1. Create a table to to handle NDP messages to resolve the MAC address of
    //    switch. This table should:
    //    - match on hdr.ndp.target_ipv6_addr (exact match)
    //    - provide action "ndp_ns_to_na" (look in snippets.p4)
    //    - default_action should be "NoAction"
    //
    // 2. Create table to handle IPv6 routing. Create a L2 my station table (hit
    //    when Ethernet destination address is the switch address). This table
    //    should not do anything to the packet (i.e., NoAction), but the control
    //    block below should use the result (table.hit) to decide how to process
    //    the packet.
    //
    // 3. Create a table for IPv6 routing. An action selector should be use to
    //    pick a next hop MAC address according to a hash of packet header
    //    fields (IPv6 source/destination address and the flow label). Look in
    //    snippets.p4 for an example of an action selector and table using it.
    //
    // You can name your tables whatever you like. You will need to fill
    // the name in elsewhere in this exercise.

    //snippets
    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

    // ndp_reply_table
    table ndp_reply_table {
        key = {
            hdr.ndp.target_ipv6_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        @name("ndp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // my_station_table
    table my_station_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            NoAction;
        }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // routing_v6_table
    action set_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }
    table routing_v6_table {
        key = {
            hdr.ipv6.dst_addr: lpm;
            hdr.ipv6.dst_addr: selector;
            hdr.ipv6.src_addr: selector;
            hdr.ipv6.flow_label: selector;
            hdr.ipv6.next_hdr: selector;
            local_metadata.l4_src_port: selector;
            local_metadata.l4_dst_port: selector;
        }
        actions = {
            set_next_hop;
        }
        implementation = ecmp_selector;
        @name("routing_v6_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }



    // *** TODO EXERCISE 6 (SRV6)
    //
    // Implement tables to provide SRV6 logic.


    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // corresponding bridging and routing entries.

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action clone_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });
    }

    table acl_table {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr:          ternary;
            hdr.ethernet.src_addr:          ternary;
            hdr.ethernet.ether_type:        ternary;
            local_metadata.ip_proto:        ternary;
            local_metadata.icmp_type:       ternary;
            local_metadata.l4_src_port:     ternary;
            local_metadata.l4_dst_port:     ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    apply {

        if (hdr.cpu_out.isValid()) {
            // *** DONE EXERCISE 4
            // Implement logic such that if this is a packet-out from the
            // controller:
            // 1. Set the packet egress port to that found in the cpu_out header
            // 2. Remove (set invalid) the cpu_out header
            // 3. Exit the pipeline here (no need to go through other tables
            standard_metadata.egress_spec = hdr.cpu_out.egress_port;
            hdr.cpu_out.setInvalid();
            exit;

        }

        bool do_l3_l2 = true;

        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            // *** DONE EXERCISE 5
            // Insert logic to handle NDP messages to resolve the MAC address of the
            // switch. You should apply the NDP reply table created before.
            // If this is an NDP NS packet, i.e., if a matching entry is found,
            // unset the "do_l3_l2" flag to skip the L3 and L2 tables, as the
            // "ndp_ns_to_na" action already set an egress port.

            if(ndp_reply_table.apply().hit) {
                do_l3_l2 = false;
            }
        }

        if (hdr.arp.isValid() && hdr.arp.opcode == ARP_REQUEST) {
            
            if(arp_reply_table.apply().hit) {
                do_l3_l2 = false;
            }

        }

        if (do_l3_l2) {

            // *** DONE EXERCISE 5
            // Insert logic to match the My Station table and upon hit, the
            // routing table. You should also add a conditional to drop the
            // packet if the hop_limit reaches 0.

            // *** TODO EXERCISE 6
            // Insert logic to match the SRv6 My SID and Transit tables as well
            // as logic to perform PSP behavior. HINT: This logic belongs
            // somewhere between checking the switch's my station table and
            // applying the routing table.

            // bool do_ipv4 = false;

            // // Gateway
            // if(my_station_table.apply().hit) {

            //     if(hdr.ipv6.isValid()) {
                    
            //         routing_v6_table.apply();
            //         if(hdr.ipv6.hop_limit == 0) { drop(); }

            //     } else if(hdr.ipv4.isValid()) {

            //         // VXLAN Upstream
            //         if (hdr.vxlan.isValid()){
                        
            //             // Decapsulate and route L2
            //             vxlan_term_table.apply();

            //         } else {

            //             // Default IPv4 routing
            //             do_ipv4 = true;
            //         }
            //     }
            // } else if(hdr.ipv4.isValid()) {
                
            //     // VXLAN Downstream
            //     vtep_table.apply();
            //     if(vxlan_segment_table.apply().hit){
            //         if(vxlan_nexthop_table.apply().hit){
            //             vxlan_encap(); // encapsulate
            //             do_ipv4 = true;
            //         }
            //     }
            // }

            // if (do_ipv4 == true){

            //     routing_v4_table.apply();
            //     if(hdr.ipv4.ttl == 0) { drop(); }
            // }

            // //first hit ecmp, then normal table, then ternary

            // //1:20am, im tired
            // if (!l2_exact_table_ecmp.apply().hit) {

            //     // L2 bridging logic. Apply the exact table first...
            //     if (!l2_exact_table.apply().hit) {
            //         // ...if an entry is NOT found, apply the ternary one in case
            //         // this is a multicast/broadcast NDP NS packet.
            //         l2_ternary_table.apply();
            //     }

            // }

            // IPv4 packet
            if (hdr.ipv4.isValid()) {

                // Switch supports this segment
                if (vxlan_segment_table.apply().hit) {

                    // Upstream
                    if (hdr.vxlan.isValid()) {

                        // Decapsulate packet
                        vxlan_term_table.apply();

                        // Route L2
                        l2_exact_table.apply();
                    
                    } else {

                        // TODO check if mac is connected

                        // Find next hop
                        if(vxlan_nexthop_table.apply().hit){
                        
                            // Encapsulate packet
                            vxlan_encap();

                            // Route ECMP Ipv4
                            routing_v4_table.apply();
                            if(hdr.ipv4.ttl == 0) { drop(); }

                        }
                    }
                }
            }

        }

        // Lastly, apply the ACL table.
        acl_table.apply();
    }
}


control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {

        if (standard_metadata.egress_port == CPU_PORT) {
            // *** DONE EXERCISE 4
            // Implement logic such that if the packet is to be forwarded to the
            // CPU port, e.g., if in ingress we matched on the ACL table with
            // action send/clone_to_cpu...
            // 1. Set cpu_in header as valid
            // 2. Set the cpu_in.ingress_port field to the original packet's
            //    ingress port (standard_metadata.ingress_port).
            hdr.cpu_in.setValid();
            hdr.cpu_in.ingress_port = standard_metadata.ingress_port;
            exit;
        }

        // If this is a multicast packet (flag set by l2_ternary_table), make
        // sure we are not replicating the packet on the same port where it was
        // received. This is useful to avoid broadcasting NDP requests on the
        // ingress port.
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}


control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        // The following is used to update the ICMPv6 checksum of NDP
        // NA packets generated by the ndp reply table in the ingress pipeline.
        // This function is executed only if the NDP header is present.
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}


control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.cpu_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
        packet.emit(hdr.arp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
