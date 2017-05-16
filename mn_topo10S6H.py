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
        for i in range(10):
            sw = "s"+str(i)
            switches.append(self.addSwitch(sw))

        # add host

        hosts = []

        hosts.append(self.addHost("h0"))
        hosts.append(self.addHost("h2"))
        hosts.append(self.addHost("h3"))
        hosts.append(self.addHost("h6"))
        hosts.append(self.addHost("h7"))
        hosts.append(self.addHost("h9"))

        # add links 


        links = [("s0","s1"),("s1","s2"),("s0","s3"),\
                 ("s0","s4"),("s1","s4"),("s1","s5"),\
                 ("s2","s5"),("s2","s6"),("s3","s4"),\
                 ("s4","s5"),("s5","s6"),("s3","s7"),\
                 ("s4","s7"),("s5","s8"),("s6","s8"),\
                 ("s6","s9"),("s7","s8"),("s8","s9"),\
                 ("h0","s0"),("h3","s3"),("h2","s2"),\
                 ("s6","h6"),("h7","s7"),("s9","h9")]
        
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