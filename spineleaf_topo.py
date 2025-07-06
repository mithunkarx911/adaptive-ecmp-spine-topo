from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class SpineLeafTopo(Topo):
    def build(self):
        # Spine switches
        spine1 = self.addSwitch('s1')
        spine2 = self.addSwitch('s2')

        # Leaf switches
        leaf1 = self.addSwitch('l1')
        leaf2 = self.addSwitch('l2')

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        # Connect hosts to leaves
        self.addLink(h1, leaf1, bw=10)
        self.addLink(h2, leaf1, bw=10)
        self.addLink(h3, leaf2, bw=10)
        self.addLink(h4, leaf2, bw=10)

        # Connect leaves to spines (full mesh)
        for leaf in [leaf1, leaf2]:
            self.addLink(leaf, spine1, bw=10)
            self.addLink(leaf, spine2, bw=10)


if __name__ == '__main__':
    setLogLevel('info')
    topo = SpineLeafTopo()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()

    print("*** Starting HTTP server on h1")
    h1 = net.get('h1')
    h1.cmd('python3 -m http.server 80 &')

    print("*** Running iperf server on h4")
    h4 = net.get('h4')
    h4.cmd('iperf -s &')

    print("*** Testing ping")
    net.pingAll()

    CLI(net)
    net.stop()