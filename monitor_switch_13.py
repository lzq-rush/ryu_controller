# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Usage example
1. Run this application:
$ ryu-manager  --observe-links ospf.switch_13.py


2. Switch struct

please see ryu/topology/switches.py

msg struct: 
{'dpid': '0000000000000001', 
'ports': [
            {'dpid': '0000000000000001', 
            'hw_addr': 'b6:b8:0b:3f:e5:86', 
            'name': 's1-eth1', 
            'port_no': '00000001'}, 
            {'dpid': '0000000000000001', 
            'hw_addr': '2e:fa:67:bd:f3:b2', 
            'name': 's1-eth2', 
            'port_no': '00000002'}
        ]
}

2. Link struct

please see ryu/topology/switches.py

note: two node will get two link.

eg: s1--s2  will get link: s1 -> s2 and link: s2->s1

msg struct

{
'dst': {'port_no': '00000001', 
         'name': 's2-eth1', 
         'hw_addr': '52:9c:f6:6d:d3:5f', 
         'dpid': '0000000000000002'}, 
'src': {'port_no': '00000001', 
        'name': 's1-eth1', 
        'hw_addr': '22:33:5a:65:de:62', 
        'dpid': '0000000000000001'}
}


3. Topology change is notified:
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_enter", "id": 1}
> {"id": 1, "jsonrpc": "2.0", "result": ""}
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_leave", "id": 2}
> {"id": 2, "jsonrpc": "2.0", "result": ""}
...
""" 


from operator import attrgetter

import ospf_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from collections import defaultdict
from ryu.topology import event
from ryu.topology.api import get_switch,get_link,get_all_host,get_host
from ryu.topology.switches import Switches
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import algorithms
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6,dhcp,ipv4,udp
from ryu.lib import mac
from ryu.lib import addrconv
from ryu.lib.dpid import dpid_to_str, str_to_dpid

ARP = arp.arp.__name__
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"



class MonitorSwitch_13(ospf_switch_13.OSPFswitch_13):

    def __init__(self, *args, **kwargs):
        super(MonitorSwitch_13, self).__init__(*args, **kwargs)


    def _monitor(self):
        while True:
            self._update_host_list()
            self._update_net_topo()
            self.logger.info("all hosts: %s",[host for host in self.hosts])
            self.send_flow_stats_request()
            # self.logger.info("link number is: %s",len(self.links))
            # self.print_topo()
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        header = 'datapath         table-id priority '
        footer = '---------------- -------- -------- '

        if len(body) == 0:
            return

        oxm_fields = body[0].match.to_jsondict()['OFPMatch']['oxm_fields']
        oxm_fields_lists = {}
        for each in oxm_fields:
            field = each['OXMT1v']['field']
            oxm_fields_lists[field] = each['OXMT1v']['value']
            length = len(field)
            header = header + field + ' '
            footer = footer + '-'*length + ' '
        
        self.logger.info('datapath         '
                         'table-id priority'
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- -------- '
                         '-------- -------- --------')
        
        for stat in [flow for flow in body if flow.priority == 1]:
            self.logger.info('%016x  %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.table_id,
                             stat.priority,
                             stat.packet_count, stat.byte_count)
        self.logger.info('------------------------------------------------')

    # def _print_flow_stats(self,)

    # @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    # def _port_stats_reply_handler(self, ev):
    #     body = ev.msg.body

    #     self.logger.info('datapath         port     '
    #                      'rx-pkts  rx-bytes rx-error '
    #                      'tx-pkts  tx-bytes tx-error')
    #     self.logger.info('---------------- -------- '
    #                      '-------- -------- -------- '
    #                      '-------- -------- --------')
    #     for stat in sorted(body, key=attrgetter('port_no')):
    #         self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
    #                          ev.msg.datapath.id, stat.port_no,
    #                          stat.rx_packets, stat.rx_bytes, stat.rx_errors,
    #                          stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    def _send_flow_stats_request(self, datapath,match,cookie=0,cookie_mask=0):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie
        cookie_mask = cookie_mask


        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                ofp.OFPTT_ALL,
                                                ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                cookie, cookie_mask,
                                                match)
        datapath.send_msg(req)


    def send_flow_stats_request(self):
        """
        match field has following arguments:
        ================ =============== ==================================
        Argument         Value           Description
        ================ =============== ==================================
        in_port          Integer 32bit   Switch input port
        in_phy_port      Integer 32bit   Switch physical input port
        metadata         Integer 64bit   Metadata passed between tables
        eth_dst          MAC address     Ethernet destination address
        eth_src          MAC address     Ethernet source address
        eth_type         Integer 16bit   Ethernet frame type
        vlan_vid         Integer 16bit   VLAN id
        vlan_pcp         Integer 8bit    VLAN priority
        ip_dscp          Integer 8bit    IP DSCP (6 bits in ToS field)
        ip_ecn           Integer 8bit    IP ECN (2 bits in ToS field)
        ip_proto         Integer 8bit    IP protocol
        ipv4_src         IPv4 address    IPv4 source address
        ipv4_dst         IPv4 address    IPv4 destination address
        tcp_src          Integer 16bit   TCP source port
        tcp_dst          Integer 16bit   TCP destination port
        udp_src          Integer 16bit   UDP source port
        udp_dst          Integer 16bit   UDP destination port
        sctp_src         Integer 16bit   SCTP source port
        sctp_dst         Integer 16bit   SCTP destination port
        icmpv4_type      Integer 8bit    ICMP type
        icmpv4_code      Integer 8bit    ICMP code
        arp_op           Integer 16bit   ARP opcode
        arp_spa          IPv4 address    ARP source IPv4 address
        arp_tpa          IPv4 address    ARP target IPv4 address
        arp_sha          MAC address     ARP source hardware address
        arp_tha          MAC address     ARP target hardware address
        ipv6_src         IPv6 address    IPv6 source address
        ipv6_dst         IPv6 address    IPv6 destination address
        ipv6_flabel      Integer 32bit   IPv6 Flow Label
        icmpv6_type      Integer 8bit    ICMPv6 type
        icmpv6_code      Integer 8bit    ICMPv6 code
        ipv6_nd_target   IPv6 address    Target address for ND
        ipv6_nd_sll      MAC address     Source link-layer for ND
        ipv6_nd_tll      MAC address     Target link-layer for ND
        mpls_label       Integer 32bit   MPLS label
        mpls_tc          Integer 8bit    MPLS TC
        mpls_bos         Integer 8bit    MPLS BoS bit
        pbb_isid         Integer 24bit   PBB I-SID
        tunnel_id        Integer 64bit   Logical Port Metadata
        ipv6_exthdr      Integer 16bit   IPv6 Extension Header pseudo-field
        pbb_uca          Integer 8bit    PBB UCA header field
                                        (EXT-256 Old version of ONF Extension)
        tcp_flags        Integer 16bit   TCP flags
                                        (EXT-109 ONF Extension)
        actset_output    Integer 32bit   Output port from action set metadata
                                        (EXT-233 ONF Extension)
        ================ =============== ==================================

        if you want to use wildcards, follow this:
            match_field = dict(eth_src = ('00:00:00:00:00:01','ff:ff:ff:ff:ff:f0'),
                               eth_dst = ('00:00:00:00:00:04','ff:ff:ff:ff:ff:f4'),
                               ipv4_src = ('10.0.0.1','255.255.255.0'),
                               ipv4_dst = ('10.0.0.4','255.255.255.0'),
                               tcp_src = (80,2),
                               tcp_dst = (27,3)
                            
            
            )
        if you want to match mac address:
            match_field = dict(eth_src = ('00:00:00:00:00:01','ff:ff:ff:ff:ff:f0'),
                               eth_dst = ('00:00:00:00:00:04','ff:ff:ff:ff:ff:f4'))
            match = ofp_parser.OFPMatch(**match_field)
            self._send_flow_stats_request(_datapath,match)

        if you want to match ip address :
            match_field = dict(eth_type=0x800,
                               ipv4_src = ('10.0.0.1','255.255.255.0'),
                               ipv4_dst = ('10.0.0.4','255.255.255.0'))
            match = ofp_parser.OFPMatch(**match_field)
            self._send_flow_stats_request(_datapath,match)

        if you want to match tcp port :
            match_field = dict(eth_type=0x800,
                               ip_proto=6,
                               tcp_src=80,
                               tcp_dst = 27)
            match = ofp_parser.OFPMatch(**match_field)
            self._send_flow_stats_request(_datapath,match)
        """


        for dpid in list(self.datapaths.keys()):
            _datapath = self._get_datapath(dpid)
            ofp_parser = _datapath.ofproto_parser
            dst_mac = '00:00:00:00:00:01'
            match = ofp_parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_src=80)
            self._send_flow_stats_request(_datapath,match)
