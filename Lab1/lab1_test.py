from mininet.topo import Topo

class Lab1_Topo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1')  # Node A
        h2 = self.addHost('h2')  # Node B
        h3 = self.addHost('h3')  # Node C
        h4 = self.addHost('h4')  # Node D

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

topos = {'lab1_topo': (lambda: Lab1_Topo())}