# monitor
self.sleep = 2
self.datapaths = {}
self.monitor_thread = hub.spawn(self._monitor)  # ENABLED
self.tx_pkt_cur = {}    # currently monitoring TX packets
self.tx_byte_cur = {}   # currently monitoring TX bytes
self.tx_pkt_int = {}    # TX packets in the last monitoring interval
self.tx_byte_int = {}    # TX bytes in the last monitoring interval

# multipath implementation
# Check if destination MAC is known (i.e., host is on same leaf)
if dst in self.mac_to_port[dpid]:
    # Intra-leaf known destination
    print(f"[DEBUG] Intra-leaf known destination: dst={dst}, out_port={self.mac_to_port[dpid][dst]}")
    out_port = self.mac_to_port[dpid][dst]
    actions = [parser.OFPActionOutput(out_port)]
    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    self.add_flow(datapath, 1000, 3, match, actions)
else:
    # Inter-leaf or unknown MAC → use bandwidth-aware ECMP
    print(f"[DEBUG] Inter-leaf or unknown MAC, using bandwidth-aware ECMP: dst={dst}")
    # Ensure monitoring dicts are initialized
    for port in [1, 2]:
        self.tx_byte_int.setdefault(dpid, {})
        self.tx_byte_int[dpid].setdefault(port, 0)
    # Select port with least recent TX bytes
    port1_bytes = self.tx_byte_int[dpid][1]
    port2_bytes = self.tx_byte_int[dpid][2]
    if port1_bytes <= port2_bytes:
        out_port = 1
    else:
        out_port = 2
    print(f"[DEBUG] Selected port {out_port} for inter-leaf traffic (port1_bytes={port1_bytes}, port2_bytes={port2_bytes})")
    actions = [parser.OFPActionOutput(out_port)]
    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    self.add_flow(datapath, 1000, 2, match, actions) 