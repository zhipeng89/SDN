
from mininet.topo import Topo

class CustomTopo(Topo):
    "Simple Source Address Verification Topology"

    #def __init__(self, linkopts1, linkopts2, linkopts3, fanout=2, **opts):
    def __init__(self):
        # Initialize topology and default options
        Topo.__init__(self)
        
        # Add your logic here ...
        # Add hosts and switches
        #host1 = self.addHost('h1', ip='192.168.0.1/24')
        #host2 = self.addHost('h2', ip='172.16.0.1/24')
        #host3 = self.addHost('h3', ip='10.0.0.1/24')
        host1 = self.addHost('h1', ip='10.0.0.1/24')
        host2 = self.addHost('h2', ip='10.0.0.2/24')
        host3 = self.addHost('h3', ip='10.0.0.3/24')

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')

        # Add links
        self.addLink(host1, switch1)
        self.addLink(host2, switch4)
        self.addLink(host3, switch3)
        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        self.addLink(switch2, switch4)
                    
topos = { 'custom': ( lambda: CustomTopo() ) }
