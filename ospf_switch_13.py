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

import topo_switch_13
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



class OSPFswitch_13(topo_switch_13.TopoSwitch_13):

    def __init__(self, *args, **kwargs):
        super(OSPFswitch_13, self).__init__(*args, **kwargs)


        self.arp_table = {}



        self.sw = {}




        self.full_path = defaultdict(lambda: defaultdict(lambda: None))

        

        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.dhcp_server = '192.168.2.100'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.hostname = str.encode('huehuehue')
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
        self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
        self.ip_addr_prefix = '10.0.0.'
        self.ip_counter = 1
        self.ip_pool = {}

        self.all_macs = []


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        dst_mac = eth.dst
        src_mac = eth.src


        #--------process IPV6 packet---
        if pkt.get_protocol(ipv6.ipv6) :  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        #------end
        

        #--------process LLDP packet--
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        #-------end

        #-------process ARP--
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src_mac
            self.logger.debug(" ARP: %s -> %s", arp_pkt.src_ip, arp_pkt.dst_ip)
        
            if self.arp_handler(msg,pkt):
                return None
        #----end

        #-----process  DHCP--

        dhcp_pkt = pkt.get_protocols(dhcp.dhcp)
        if dhcp_pkt:
            self.dhcp_handler(datapath, in_port, pkt)
            return None
        #----end

        #---process IGMP------
        # simply drop IGMP packet
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        dst_ipv4 = ipv4_pkt.dst
        src_ipv4 = ipv4_pkt.src
        if dst_ipv4 == '224.0.0.22' or dst_ipv4 == '224.0.0.251':
            match = parser.OFPMatch(ipv4_dst=dst_ipv4)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None
        #-----end

        # type of dpid is 16 int
        dpid = datapath.id

        
        # print(pkt.protocols)
        # print("------end------")
        

        # after filte ARP, IGMP, DHCP packet, log this packet_in message
        self.logger.debug("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        self.logger.debug("src_mac: %s src_ip_4: %s ----> dst_mac: %s dst_ip_4: %s",src_mac,src_ipv4,dst_mac,dst_ipv4)


        paths = self.get_detail_path(src_mac,dst_mac)
        if paths is not None and len(paths) > 0:
            out_port = self.install_path(paths,dst_mac,dpid,parser,ofproto,msg)
        else:

            # out_port = ofproto.OFPP_FLOOD
            return 

        # print("path is: ",paths)


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data


        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def install_path(self,paths,dst,in_dpid,parser,ofproto,msg):

        nodes = list(paths.keys())
        out_port = 0
        #nodes = [int(node) for node in list(paths.keys())]
        # if in_dpid not in nodes:
        #     return 
        self.logger.debug("try to install path for : %s",nodes)
        self.logger.debug("origin dpid is %s",in_dpid)
        for node in nodes:
            target_dpid = str_to_dpid(node)
            if target_dpid == in_dpid:
                out_port = paths[node][1]
            target_in_port = paths[node][0]
            target_out_port = paths[node][1]

            target_actions = [parser.OFPActionOutput(target_out_port)]

            # target_match = parser.OFPMatch(in_port=target_in_port, eth_dst=dst)
            target_match = parser.OFPMatch(eth_dst=dst)

            target_datapath = self._get_datapath(target_dpid)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(target_datapath, 1, target_match, target_actions, msg.buffer_id)
            else:
                self.add_flow(target_datapath, 1, target_match, target_actions)

        return out_port


    def update_path(self):
        # if :
        #     return
        self.logger.debug("all hosts: %s",self.hosts.keys())
        self.full_path = algorithms.get_all_path(self.hosts,self.net_topo)

    
    
    def get_detail_path(self,src,dst):
        return algorithms.get_path(src,dst,self.full_path,self.net_topo)




    def assemble_ack(self, pkt, dpid):
        dpid_yiaddr = self.get_ip(dpid)
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag=51, value=str.encode('8640')))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value=str.encode('\x05')))
                                      
        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=self.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=self.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=dpid_yiaddr,
                                       xid=req.xid,
                                       options=req.options))
        self.logger.debug("ASSEMBLED ACK")
        return ack_pkt


    def assemble_offer(self, pkt, dpid):
        dpid_yiaddr = self.get_ip(dpid)
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 55))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 53))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 12))
        disc.options.option_list.insert(
            0, dhcp.option(tag=1, value=self.bin_netmask))
        disc.options.option_list.insert(
            0, dhcp.option(tag=3, value=self.bin_server))
        disc.options.option_list.insert(
            0, dhcp.option(tag=6, value=self.bin_dns))
        disc.options.option_list.insert(
            0, dhcp.option(tag=12, value=self.hostname))
        disc.options.option_list.insert(
            0, dhcp.option(tag=53, value=str.encode('\x02')))
        disc.options.option_list.insert(
            0, dhcp.option(tag=54, value=self.bin_server))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=disc_eth.ethertype, dst=disc_eth.src, src=self.hw_addr))
        offer_pkt.add_protocol(
            ipv4.ipv4(dst=disc_ipv4.dst, src=self.dhcp_server, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        offer_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=disc_eth.src,
                                         siaddr=self.dhcp_server,
                                         boot_file=disc.boot_file,
                                         yiaddr=dpid_yiaddr,
                                         xid=disc.xid,
                                         options=disc.options))
        self.logger.debug("ASSEMBLED OFFER: ")
        return offer_pkt


    def dhcp_handler(self,datapath,in_port,pkt):
        dhcp_pkt = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = self.get_state(dhcp_pkt)
        self.logger.debug("NEW DHCP -->%s<-- PACKET RECEIVED" %
                         (dhcp_state))
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packetOut(datapath, in_port, self.assemble_offer(pkt,datapath.id))
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packetOut(datapath, in_port, self.assemble_ack(pkt,datapath.id))
        else:
            return

    def _send_packetOut(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.debug("packet-out DHCP " )
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def get_ip(self,dpid):
        if dpid not in self.ip_pool:
            ip = self.ip_addr_prefix+str(self.ip_counter)
            self.ip_counter+=1
            self.ip_pool[dpid] = ip
        else:
            ip = self.ip_pool[dpid]
        return ip

    def get_state(self, dhcp_pkt):

        opt_list = [opt for opt in dhcp_pkt.options.option_list if opt.tag == 53]

        self.logger.debug("opt_list: %s",opt_list[0].value)

        dhcp_state = ord(
            [opt for opt in dhcp_pkt.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state  

    def arp_handler(self, msg,pkt):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocols(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR:  # and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip
            arp_src_ip = arp_pkt.src_ip

            if (datapath.id, arp_src_ip, arp_dst_ip) in self.sw:
                # packet come back at different port.
                if self.sw[(datapath.id, arp_src_ip, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                # self.sw.setdefault((datapath.id, eth_src, arp_dst_ip), None)
                self.sw[(datapath.id, arp_src_ip, arp_dst_ip)] = in_port
                # print self.sw


        # Try to reply arp request
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                hwtype = arp_pkt.hwtype
                proto = arp_pkt.proto
                hlen = arp_pkt.hlen
                plen = arp_pkt.plen
                arp_src_ip = arp_pkt.src_ip
                arp_dst_ip = arp_pkt.dst_ip
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    self.logger.debug("Send one ARP_Reply---")
                    return True
        return False










    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def _flow_stats_reply_handler(self, ev):
    #     body = ev.msg.body

    #     self.logger.info('datapath         '
    #                      'in-port  eth-dst           '
    #                      'out-port packets  bytes')
    #     self.logger.info('---------------- '
    #                      '-------- ----------------- '
    #                      '-------- -------- --------')
    #     for stat in sorted([flow for flow in body if flow.priority == 1],
    #                        key=lambda flow: (flow.match['in_port'],
    #                                          flow.match['eth_dst'])):
    #         self.logger.info('%016x %8x %17s %8x %8d %8d',
    #                          ev.msg.datapath.id,
    #                          stat.match['in_port'], stat.match['eth_dst'],
    #                          stat.instructions[0].actions[0].port,
    #                          stat.packet_count, stat.byte_count)

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

    # def send_flow_stats_request(self, datapath,cookie=0,cookie_mask=0):
    #     ofp = datapath.ofproto
    #     ofp_parser = datapath.ofproto_parser

    #     cookie = cookie
    #     cookie_mask = cookie_mask

    #     match = ofp_parser.OFPMatch()
    #     req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
    #                                             ofp.OFPTT_ALL,
    #                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
    #                                             cookie, cookie_mask,
    #                                             match)
    #     datapath.send_msg(req)








