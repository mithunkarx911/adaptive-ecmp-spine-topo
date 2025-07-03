from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class SpineLeafTopo(Topo):
    def build(self):
        # Add spine switches
        spine1 = self.addSwitch('s1')
        spine2 = self.addSwitch('s2')

        # Add leaf switches
        leaf1 = self.addSwitch('s3')
        leaf2 = self.addSwitch('s4')
        leaf3 = self.addSwitch('s5')

        # Connect leafs to spines (full mesh)
        for leaf in [leaf1, leaf2, leaf3]:
            self.addLink(leaf, spine1, cls=TCLink, bw=10)
            self.addLink(leaf, spine2, cls=TCLink, bw=10)

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')

        # Connect hosts to leaf switches
        self.addLink(h1, leaf1, cls=TCLink, bw=10)
        self.addLink(h2, leaf2, cls=TCLink, bw=10)
        self.addLink(h3, leaf3, cls=TCLink, bw=10)

if __name__ == '__main__':
    setLogLevel('info')
    topo = SpineLeafTopo()

    # Explicit controller connection
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
                  link=TCLink)

    net.start()
    CLI(net)
    net.stop()
