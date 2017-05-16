#!/usr/bin/python                                                                            
                                                                                             
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import Controller



class SmallSwitchTopo(Topo):
    def build(self, n=10):
        switches = []

        # add swtich
        switches.append(self.addSwitch("s1"))
        switches.append(self.addSwitch("s2"))
        # add host

        hosts = []

        hosts.append(self.addHost("h1"))
        hosts.append(self.addHost("h2"))

        # add links 


        links = [("s1","s2"),("s2","h2"),("s1","h1")]
        
        for link in links:
                self.addLink(link[0],link[1])




def simpleTest():
    "Create and test a simple network"
    topo = SmallSwitchTopo(n=4)
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()


topos = {'mytopo': SmallSwitchTopo}
tests = {'mytest': simpleTest}


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()