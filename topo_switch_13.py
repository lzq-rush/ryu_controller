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

3. Host struct



3. Topology change is notified:
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_enter", "id": 1}
> {"id": 1, "jsonrpc": "2.0", "result": ""}
< {"params": [{"ports": [{"hw_addr": "56:c7:08:12:bb:36", "name": "s1-eth1", "port_no": "00000001", "dpid": "0000000000000001"}, {"hw_addr": "de:b9:49:24:74:3f", "name": "s1-eth2", "port_no": "00000002", "dpid": "0000000000000001"}], "dpid": "0000000000000001"}], "jsonrpc": "2.0", "method": "event_switch_leave", "id": 2}
> {"id": 2, "jsonrpc": "2.0", "result": ""}
...
""" 


from operator import attrgetter

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from collections import defaultdict
from ryu.topology import event
from ryu.topology.switches import *
from ryu.lib.dpid import dpid_to_str, str_to_dpid

import threading


# this mutex is for self.hosts
# when EventHostAdd is occur, it needs add host to self.hosts
# but def _update_host_list also has to update self.hosts
# def _update_host_list is working at other thread, so needs mutex
mutex = threading.Lock()  




class TopoSwitch_13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(TopoSwitch_13, self).__init__(*args, **kwargs)
        self.monitor_thread = hub.spawn(self._monitor)
        
        #---topology---------
        self.dps = {}
        self.port_state = {}
        self.links = {}
        self.hosts = HostState()

        # self.switch_macs = set()

        # links has no weight!!
        self.net_topo = defaultdict(lambda: defaultdict(lambda: None))

        #--------------




    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self,ev):
        msg = ev.switch
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

        
        self._register(msg.dp)
        self.logger.info('Switch enter: %s',dpid_to_str(msg.dp.id))


    def _register(self,dp):
        assert dp.id is not None
        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            # print("register ports: ",dp.ports.values())
            for port in dp.ports.values():
                # self.switch_macs.add(port.hw_addr)
                self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dps:
            if (self.dps[dp.id] == dp):
                del self.dps[dp.id]
                del self.port_state[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dps:
            switch = Switch(self.dps[dpid])
            for ofpport in self.port_state[dpid].values():
                switch.add_port(ofpport)
            return switch

    def _is_edge_port(self, port):
        for link in self.links:
            if port == link.src or port == link.dst:
                return False

        return True

    # @set_ev_cls(event.EventSwitchLeave)
    # def _event_switch_leave_handler(self, ev):
    #     self.all_switches._unregister(ev.switch.dp)
    #     self.logger.info('Switch Leave: %s',dpid_to_str(ev.switch.dp.id))

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        msg = ev.link
        self.links[msg] = 1
        self.logger.info('event_link_add ')

    def _update_host_list(self):

        if mutex.acquire():
        
            for host_mac in self.hosts:
                host = self.hosts[host_mac]
                port = host.port
                if not self._is_edge_port(port):
                    del(self.hosts[host_mac])
                    mutex.release()
                    return
            mutex.release()    

    # @handler.set_ev_cls(event.EventLinkDelete)
    # def _event_link_delete_handler(self, ev):
    #     msg = ev.link.to_dict()
        
    #     print('event_link_delete')
    #     print(msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):

        msg = ev.host
        in_port = msg.port

        if self._is_edge_port(in_port):
            if mutex.acquire():
                self.hosts.add(msg)
                mutex.release()
            src_dpid = msg.mac
            self.logger.info('event_host_add %s',src_dpid)

    def _monitor(self):
        while True:
            self._update_host_list()
            self.logger.info("all hosts: %s",[host for host in self.hosts])
            self.logger.info("link number is: %s",len(self.links))
            hub.sleep(10)





