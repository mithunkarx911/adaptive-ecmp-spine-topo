from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import hub
import networkx as nx
import time
import collections # Import collections for defaultdict

class AdaptiveECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 2  # seconds

    # Congestion Control Parameters
    CONGESTION_THRESHOLD = 0.80  # Link utilization percentage (e.g., 0.80 for 80%)
    CONGESTION_PENALTY_FACTOR = 100 # Multiplier for weight if congested (makes path very undesirable)
    
    # Default port speed in bits per second (e.g., 1 Gbps)
    DEFAULT_PORT_SPEED_BPS = 1_000_000_000

    def __init__(self, *args, **kwargs):
        super(AdaptiveECMP, self).__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.datapaths = {}
        self.mac_to_port = {}
        
        # Flow counters: (src_mac, dst_mac): {'sent': count, 'recv': count, 'bytes': total_bytes}
        self.flow_counters = collections.defaultdict(lambda: {'sent': 0, 'recv': 0, 'bytes': 0})
        
        # RTT stats per switch: dpid: [list of RTTs in ms]
        self.rtt_stats = collections.defaultdict(list) 
        # Timestamp of last echo request sent per datapath for accurate RTT
        self.echo_request_time = {} 

        # For link utilization calculation
        # (dpid, port_no): (tx_bytes, timestamp)
        self.link_tx_bytes_prev = {}  
        # (dpid, port_no): (rx_bytes, timestamp)
        self.link_rx_bytes_prev = {}  
        # (src_dpid, dst_dpid): current utilization %
        self.link_utilization = collections.defaultdict(float) 
        # (src_dpid, dst_dpid): True/False if link is congested
        self.link_congestion_status = collections.defaultdict(bool) 

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a default low-priority rule to send unmatched packets to controller
        # This ensures that initial packets of a flow are sent to the controller for path determination
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions) # Priority 0, lowest priority
        self.logger.info("[BOOT] Default CONTROLLER rule installed on switch %s", datapath.id)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        """
        Discovers switches and links in the network topology.
        Initializes graph nodes and edges.
        """
        switch_list = get_switch(self, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.add_nodes_from(switches)
        self.logger.info("[TOPO] Detected switches: %s", switches)

        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            # Initialize link weight to 1.0 (base cost). This will be dynamically updated
            # based on utilization for congestion control.
            self.graph.add_edge(src, dst, port=port, weight=1.0)
            self.logger.info("[TOPO] Link added: %s -> %s via port %s", src, dst, port)

    def _monitor(self):
        """
        Periodically requests statistics from switches and prints network stats.
        Runs in a separate Ryu hub thread.
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self._send_echo_request(dp) # Send echo requests for RTT measurement
            self._print_stats()
            hub.sleep(self.STATS_INTERVAL)

    def _print_stats(self):
        """
        Prints current network statistics including flow counters, link utilization,
        and congestion status.
        """
        self.logger.info("\n------ Network Stats ------")
        # Print flow-specific stats
        for (src_mac, dst_mac), data in self.flow_counters.items():
            # Note: RTT for flows would require more advanced probing or flow monitoring.
            # Here, we only have switch RTT.
            sent = data['sent']
            recv = data['recv']
            # Avoid division by zero if no packets were sent
            loss_pct = ((sent - recv) / sent * 100) if sent > 0 else 0
            throughput_mbps = (data['bytes'] * 8) / (self.STATS_INTERVAL * 1_000_000)

            self.logger.info("Flow %s -> %s: Recv Pkts=%d, Sent Pkts=%d, Loss=%.2f%%, Throughput=%.2f Mbps",
                              src_mac, dst_mac, recv, sent, loss_pct, throughput_mbps)

        self.logger.info("\n------ Link Utilization & Congestion ------")
        # Print link utilization and congestion status
        for (src_dpid, dst_dpid), util in self.link_utilization.items():
            congestion_status = "CONGESTED" if self.link_congestion_status[(src_dpid, dst_dpid)] else "NORMAL"
            self.logger.info("Link %s -> %s Utilization: %.2f %% (%s)", src_dpid, dst_dpid, util, congestion_status)
        
        self.logger.info("---------------------------\n")

    def _send_echo_request(self, datapath):
        """
        Sends an OFPEchoRequest to the specified datapath to measure RTT.
        """
        # Store timestamp per datapath for accurate RTT calculation
        self.echo_request_time[datapath.id] = time.time()
        req = datapath.ofproto_parser.OFPEchoRequest(datapath, data=b'ryu_ping')
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def _echo_reply_handler(self, ev):
        """
        Handles OFPEchoReply messages to calculate and log RTT for switches.
        """
        dpid = ev.msg.datapath.id
        if dpid in self.echo_request_time:
            rtt = (time.time() - self.echo_request_time[dpid]) * 1000  # RTT in milliseconds
            self.rtt_stats[dpid].append(rtt)
            self.logger.info("[RTT] Switch %s echo RTT = %.2f ms", dpid, rtt)
            # Maintain a limited history of RTT samples
            if len(self.rtt_stats[dpid]) > 10: # Keep last 10 samples
                self.rtt_stats[dpid].pop(0)
        else:
            self.logger.warning("[RTT] Received echo reply from %s but no corresponding request time recorded.", dpid)

    def _request_stats(self, datapath):
        """
        Requests port statistics from the given datapath.
        """
        parser = datapath.ofproto_parser
        # Request Port Stats for utilization calculation
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)
        # You could also request Flow Stats here for more accurate flow_counters
        # req_flow = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req_flow)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Handles OFPPortStatsReply messages to calculate link utilization
        and update graph edge weights for congestion control.
        """
        dpid = ev.msg.datapath.id
        now = time.time()
        for stat in ev.msg.body:
            port_no = stat.port_no
            tx_bytes = stat.tx_bytes
            rx_bytes = stat.rx_bytes # Capture rx_bytes for completeness

            # Calculate TX utilization for outgoing links
            tx_key = (dpid, port_no)
            if tx_key in self.link_tx_bytes_prev:
                prev_tx_bytes, prev_time = self.link_tx_bytes_prev[tx_key]
                time_diff = now - prev_time
                
                if time_diff > 0:
                    tx_diff_bytes = tx_bytes - prev_tx_bytes
                    tx_bps = (tx_diff_bytes * 8) / time_diff # Bandwidth in bits per second
                    
                    # Find the corresponding outgoing link in the graph
                    # and update its weight based on utilization
                    for src, dst, data in self.graph.edges(data=True):
                        if src == dpid and data.get('port') == port_no:
                            link_key = (src, dst)
                            
                            # Calculate utilization as a percentage of default port speed
                            utilization = (tx_bps / self.DEFAULT_PORT_SPEED_BPS) * 100
                            self.link_utilization[link_key] = round(utilization, 2)
                            
                            # Determine congestion status
                            is_congested = (utilization / 100.0) >= self.CONGESTION_THRESHOLD
                            self.link_congestion_status[link_key] = is_congested
                            
                            # Update graph edge weight for congestion control
                            # A base weight of 1.0
                            # Add a penalty based on utilization. If congested, apply a high penalty.
                            new_weight = 1.0 + (utilization / 100.0) # Linear increase
                            if is_congested:
                                new_weight += self.CONGESTION_PENALTY_FACTOR # Add a large fixed penalty
                            
                            self.graph[src][dst]['weight'] = new_weight
                            
                            self.logger.debug("[UTIL] Link %s->%s (port %s) Util: %.2f%%, Congested: %s, New Weight: %.2f",
                                              src, dst, port_no, utilization, is_congested, new_weight)
                            break # Found the link, move to next stat

            self.link_tx_bytes_prev[tx_key] = (tx_bytes, now)
            self.link_rx_bytes_prev[tx_key] = (rx_bytes, now) # Update rx_bytes_prev too

    def add_flow(self, datapath, priority, match, actions, idle_timeout=60, hard_timeout=300):
        """
        Helper function to add a flow entry to a datapath.
        Includes idle and hard timeouts for dynamic flow management.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug("Flow added on sw:%d, priority:%d, match:%s, actions:%s, idle_to:%d, hard_to:%d",
                          datapath.id, priority, match, actions, idle_timeout, hard_timeout)

    def _get_least_utilized_path(self, src, dst):
        """
        Finds the path with the least accumulated weight (i.e., least utilized)
        between source and destination using Dijkstra's algorithm.
        """
        try:
            # nx.shortest_path uses Dijkstra's algorithm by default when 'weight' is specified.
            # It finds the path with the minimum sum of edge weights.
            path = nx.shortest_path(self.graph, source=src, target=dst, weight='weight')
            path_cost = nx.path_weight(self.graph, path, weight='weight')
            self.logger.info("[PATH] Selected path from %s to %s: %s (Cost: %.2f)",
                             src, dst, path, path_cost)
            return path
        except nx.NetworkXNoPath:
            self.logger.warning("[PATH] No path found from %s to %s", src, dst)
            return []
        except nx.NodeNotFound:
            self.logger.error("[PATH] Source or destination node not found in graph: %s or %s", src, dst)
            return []

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handles incoming packets. Performs MAC learning, determines destination,
        finds the least utilized path, installs flow rules, and forwards the packet.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4) # Extract IP packet if present

        # Filter out common control protocols to avoid processing them as data traffic
        if eth.ethertype == 0x88CC: # LLDP
            return
        if eth.ethertype == 0x8942: # BFD
            return
        # Add other filters if necessary (e.g., ARP, IPv6 if not handled)

        dst_mac = eth.dst
        src_mac = eth.src

        self.logger.info("[PACKET_IN] sw:%s in_port:%s src:%s dst:%s", dpid, in_port, src_mac, dst_mac)

        # MAC learning: Associate source MAC with the ingress port on this switch
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Find the datapath where the destination MAC is known
        dst_dpid = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                break

        # Update flow counters for the current packet
        key = (src_mac, dst_mac)
        self.flow_counters[key]['recv'] += 1
        self.flow_counters[key]['bytes'] += len(msg.data)

        if dst_dpid is None:
            # Destination MAC is unknown, flood the packet to discover it
            self.logger.info("[MAC_LOOKUP] Destination MAC %s unknown — flooding", dst_mac)
            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        # Determine the least utilized path from the current switch to the destination switch
        path = self._get_least_utilized_path(dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.warning("[PATH] No valid path found from %s to %s for %s -> %s. Flooding.", dpid, dst_dpid, src_mac, dst_mac)
            # If no path found (e.g., topology issue, isolated host), flood as a fallback
            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        # Install flow rules along the selected path on each switch in the path
        # This ensures subsequent packets of the same flow follow this path
        for i in range(len(path) - 1):
            curr_sw = path[i]
            next_sw = path[i + 1]
            
            # Get the output port from the current switch to the next switch in the path
            try:
                out_port = self.graph[curr_sw][next_sw]['port']
            except KeyError:
                self.logger.error("Graph link data missing for %s -> %s. Cannot install flow.", curr_sw, next_sw)
                continue # Skip this part of the path if link data is incomplete

            dp = self.datapaths.get(curr_sw) # Get the datapath object for the current switch
            if not dp:
                self.logger.error("Datapath %s not found for path installation. Skipping flow rule.", curr_sw)
                continue

            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            
            # Match on source and destination MAC for more specific flows.
            # This allows different (src,dst) flows to potentially take different paths
            # if the network conditions change or if ECMP is implemented.
            match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            
            # Install flow rule with idle and hard timeouts.
            # Priority 10 ensures these specific rules take precedence over the default flood rule (priority 0).
            self.add_flow(dp, 10, match, actions) 
            self.logger.info("[FLOW] Rule installed on sw=%s: src_mac=%s dst_mac=%s -> port %s", curr_sw, src_mac, dst_mac, out_port)

        # Forward the current packet using the first hop of the chosen path
        # The output port for the current switch (dpid) is the port leading to the next hop in the path
        next_hop_dpid = path[1]
        
        # Determine the actual output port on the current switch (dpid) for the packet
        if dpid == next_hop_dpid: # This case occurs if the destination is directly connected to the current switch
            final_out_port = self.mac_to_port[dpid][dst_mac]
        else:
            try:
                final_out_port = self.graph[dpid][next_hop_dpid]['port']
            except KeyError:
                self.logger.error("Could not find port from %s to %s in graph for packet out. Path might be broken. Flooding.", dpid, next_hop_dpid)
                # Fallback to flood if the first segment of the path is missing
                actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
                return

        actions = [datapath.ofproto_parser.OFPActionOutput(final_out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        self.logger.info("[FORWARD] Sent packet from %s to %s via port %s on switch %s", src_mac, dst_mac, final_out_port, dpid)

        # Increment 'sent' count for the flow, assuming the packet is successfully sent out
        self.flow_counters[key]['sent'] += 1