from mininet.topo import Topo

class Lab2_Topo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        s8 = self.addSwitch('s8')

        # Add links between switches
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s6)
        self.addLink(s2, s3)
        self.addLink(s2, s4)
        self.addLink(s2, s5)
        self.addLink(s2, s7)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s4, s8)
        self.addLink(s5, s7)
        self.addLink(s5, s8)
        self.addLink(s6, s7)
        #self.addLink(s7, s8)

        # Add links between hosts and switches
        self.addLink(h1, s1)
        self.addLink(h2, s3)
        self.addLink(h3, s7)
        self.addLink(h4, s5)
        self.addLink(h5, s5)
        self.addLink(h6, s8)
        self.addLink(h7, s8)
        self.addLink(h8, s6)
        self.addLink(h9, s4)

topos = {'lab2_topo': (lambda: Lab2_Topo())}