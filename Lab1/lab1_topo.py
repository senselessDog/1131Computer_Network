from mininet.topo import Topo

class Lab1_Topo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('A')  # Node A
        h2 = self.addHost('B')  # Node B
        h3 = self.addHost('C')  # Node C
        h4 = self.addHost('D')  # Node D

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Add links
        self.addLink(h1, s3, port1=1, port2=1)
        self.addLink(h2, s1, port1=1, port2=3)
        self.addLink(h3, s2, port1=1, port2=3)
        self.addLink(h4, s2, port1=1, port2=2)
        self.addLink(s1, s2, port1=2, port2=4)
        self.addLink(s2, s3, port1=1, port2=2)
        self.addLink(s1, s3, port1=1, port2=3)


topos = {'lab1_topo': (lambda: Lab1_Topo())}