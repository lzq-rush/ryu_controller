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

import monitor_of13


from ryu.controller.handler import set_ev_cls
from collections import defaultdict
from ryu.topology import event
from ryu.topology.api import get_switch,get_link
from ryu.lib import hub

sws = []
adjacency = defaultdict(lambda: defaultdict(lambda: None))
path_map = defaultdict(lambda: defaultdict(lambda: (None, None)))

class OspfSwitch(monitor_of13.SimpleMonitor13):

    def __init__(self, *args, **kwargs):
        super(OspfSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.all_switches = defaultdict(lambda: defaultdict(lambda: None))

        self.net_topo = defaultdict(lambda: defaultdict(lambda: None))


    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self,ev):

        msg = ev.switch.to_dict()
    #    msg struct: 
    #    {'dpid': '0000000000000001', 
    #    'ports': [
    #               {'dpid': '0000000000000001', 
    #               'hw_addr': 'b6:b8:0b:3f:e5:86', 
    #               'name': 's1-eth1', 
    #               'port_no': '00000001'}, 
    #               {'dpid': '0000000000000001', 
    #               'hw_addr': '2e:fa:67:bd:f3:b2', 
    #               'name': 's1-eth2', 
    #               'port_no': '00000002'}
    #             ]
    #     }

        # todo consider duplicate switch

        self.all_switches[msg['dpid']]['ports'] = msg['ports']
        self.logger.info('Switch enter: %s',msg['dpid'])



    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        msg = ev.switch.to_dict()
        self.logger.info('Switch Leave: %s',msg['dpid'])

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        msg = ev.link.to_dict()

        src_dpid = msg['src']['dpid']
        dst_dpid = msg['dst']['dpid']

        self.add_link(src_dpid,dst_dpid,msg)
        self.logger.info('event_link_add %s %s',src_dpid,dst_dpid)

    # @handler.set_ev_cls(event.EventLinkDelete)
    # def _event_link_delete_handler(self, ev):
    #     msg = ev.link.to_dict()
        
    #     print('event_link_delete')
    #     print(msg)


    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        msg = ev.host.to_dict()

        # direct link to switch's port info
        dst_port = msg['port']

        # host port info
        src_port = {'hw_addr': msg['mac'],
                    'dpid':msg['mac'],
                    'port_no':'00000001',
                    'name':'host'}

        src_dpid = msg['mac']
        dst_dpid = msg['port']['dpid']

        link_info_1 = {'src':src_port,'dst':dst_port}
        link_info_2 = {'src':dst_port,'dst':src_port}

        self.add_link(src_dpid,dst_dpid,link_info_1)

        self.add_link(dst_dpid,src_dpid,link_info_2)
        
        self.logger.info('event_host_add %s',src_dpid)
        

    
    def add_link(self,src,dst,msg):
        self.net_topo[src][dst] = msg




    