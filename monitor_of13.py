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

from operator import attrgetter

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from collections import defaultdict



class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flows = defaultdict(lambda: defaultdict(lambda: None))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            #print("size of dp "+str(len(self.datapaths)))
            for dp in self.datapaths.values():
                #self._request_stats(dp)
                self.send_flow_stats_request(dp,1,1)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

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

    def send_flow_stats_request(self, datapath,cookie=0,cookie_mask=0):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie
        cookie_mask = cookie_mask

        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                ofp.OFPTT_ALL,
                                                ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                cookie, cookie_mask,
                                                match)
        datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # flows = []
        self.logger.info('table_id cookie   '
                            'packet_count     byte_count')
        self.logger.info('-------- -------- '
                            '---------------- ----------')
        for stat in ev.msg.body:
            # flows.append('table_id=%s '
            #                 'duration_sec=%d duration_nsec=%d '
            #                 'priority=%d '
            #                 'idle_timeout=%d hard_timeout=%d flags=0x%04x '
            #                 'cookie=%d packet_count=%d byte_count=%d '
            #                 'match=%s instructions=%s' %
            #                 (stat.table_id,
            #                 stat.duration_sec, stat.duration_nsec,
            #                 stat.priority,
            #                 stat.idle_timeout, stat.hard_timeout, stat.flags,
            #                 stat.cookie, stat.packet_count, stat.byte_count,
            #                 stat.match, stat.instructions))
            if(self.is_new_flow(stat.cookie)):
                self.flows[stat.cookie]["table_id"] = stat.table_id
                self.flows[stat.cookie]["packet_count"] = [stat.packet_count]
                self.flows[stat.cookie]["byte_count"] = [stat.byte_count]
            else:
                self.flows[stat.cookie]["packet_count"].append(stat.packet_count)
                self.flows[stat.cookie]["byte_count"].append(stat.byte_count)

            self.logger.info('%8d %8d %16d %16d',stat.table_id,stat.cookie,
                                                  stat.packet_count,stat.byte_count)

        
        # self.logger.info('FlowStats: %s', flows)


    def is_new_flow(self,flow_cookie):
        if len(self.flows[flow_cookie]) == 0:
            return True
        return False