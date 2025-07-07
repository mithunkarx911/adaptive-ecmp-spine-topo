from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
import networkx as nx
import time


class AdaptiveECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 2  # seconds

    def __init__(self, *args, **kwargs):
        super(AdaptiveECMP, self).__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.port_stats = {}
        self.datapaths = {}
        self.mac_to_port = {}
        self.flow_counters = {}       # (src, dst): {'sent': 0, 'recv': 0, 'bytes': 0}
        self.rtt_stats = {}           # (src, dst): [list of RTTs]
        self.link_tx_prev = {}        # (dpid, port): (tx_bytes, timestamp)
        self.link_util = {"s1": 0.0, "s2": 0.0}  # utilization in %
        self.port_speed = 10_000_000  # 10 Mbps in bits
        self.echo_sent = time.time()
        self.topo_ready = False
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("[BOOT] Default controller rule installed on switch %s", datapath.id)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.add_nodes_from(switches)
        self.logger.info("[TOPO] Detected switches: %s", switches)

        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            self.graph.add_edge(src, dst, port=port, weight=1)
            self.logger.info("[TOPO] Link added: %s -> %s via port %s", src, dst, port)

        self.topo_ready = True

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self._send_echo_request(dp)
            self._print_stats()
            hub.sleep(self.STATS_INTERVAL)

    def _print_stats(self):
        self.logger.info("\n------ Network Stats ------")
        for (src, dst), data in self.flow_counters.items():
            rtts = self.rtt_stats.get((src, dst), [])
            avg_rtt = sum(rtts) / len(rtts) if rtts else 0
            max_rtt = max(rtts) if rtts else 0
            sent = data.get('sent', data['recv'])
            recv = data['recv']
            loss_pct = ((sent - recv) / sent * 100) if sent > 0 else 0
            throughput_mbps = (data['bytes'] * 8) / (self.STATS_INTERVAL * 1_000_000)

            self.logger.info("Flow %s -> %s: Packets=%d, Loss=%.2f%%, Avg RTT=%.2f ms, Max RTT=%.2f ms, Throughput=%.2f Mbps",
                             src, dst, recv, loss_pct, avg_rtt, max_rtt, throughput_mbps)

        self.logger.info("Spine-1 Utilization: %.2f %%", self.link_util.get("s1", 0.0))
        self.logger.info("Spine-2 Utilization: %.2f %%", self.link_util.get("s2", 0.0))

    def _send_echo_request(self, datapath):
        self.echo_sent = time.time()
        req = datapath.ofproto_parser.OFPEchoRequest(datapath, data=b'')
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def _echo_reply_handler(self, ev):
        rtt = (time.time() - self.echo_sent) * 1000  # ms
        dpid = ev.msg.datapath.id
        self.logger.info("[RTT] Switch %s echo RTT = %.2f ms", dpid, rtt)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        if not self.topo_ready:
            self.logger.warning("[TOPO] Topology not ready — flooding")
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

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if not ip_pkt and not arp_pkt:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        self.logger.info("[PACKET_IN] sw:%s in_port:%s src:%s dst:%s", dpid, in_port, src_mac, dst_mac)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if arp_pkt:
            self.logger.info("[ARP] Flooding ARP packet")
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

        dst_dpid = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                break

        key = (src_mac, dst_mac)
        flow = self.flow_counters.setdefault(key, {'sent': 0, 'recv': 0, 'bytes': 0})
        flow['recv'] += 1
        flow['bytes'] += len(msg.data)

        if dst_dpid is None:
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

        path = self._get_least_utilized_path(dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.warning("[PATH] No valid path found from %s to %s", dpid, dst_dpid)
            return

        for i in range(len(path) - 1):
            curr_sw = path[i]
            next_sw = path[i + 1]
            out_port = self.graph[curr_sw][next_sw]['port']
            dp = self.datapaths[curr_sw]
            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst=dst_mac, eth_src=src_mac)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(mod)
            self.logger.info("[FLOW] Rule installed: sw=%s src=%s dst=%s -> port %s", curr_sw, src_mac, dst_mac, out_port)

        out_port = self.graph[dpid][path[1]]['port']
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        self.logger.info("[FORWARD] Sent packet from %s to %s via port %s", src_mac, dst_mac, out_port)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()
        for stat in ev.msg.body:
            port_no = stat.port_no
            tx_bytes = stat.tx_bytes
            key = (dpid, port_no)

            if key in self.link_tx_prev:
                tx_diff = tx_bytes - self.link_tx_prev[key][0]
                time_diff = now - self.link_tx_prev[key][1]
                if time_diff > 0:
                    bw_bps = (tx_diff * 8) / time_diff
                    utilization = (bw_bps / self.port_speed) * 100
                    sw_name = f"s{dpid}"
                    if sw_name in self.link_util:
                        self.link_util[sw_name] = round(utilization, 2)

            self.link_tx_prev[key] = (tx_bytes, now)

    def _get_least_utilized_path(self, src, dst):
        try:
            paths = list(nx.all_shortest_paths(self.graph, src, dst))
        except nx.NetworkXNoPath:
            return []

        min_load = float('inf')
        best_path = None

        for path in paths:
            load = sum(self.port_stats.get(path[i], {}).get(self.graph[path[i]][path[i + 1]]['port'], 0)
                       for i in range(len(path) - 1))
            if load < min_load:
                min_load = load
                best_path = path

        self.logger.info("[PATH] Selected path from %s to %s: %s (load=%s)", src, dst, best_path, min_load)
        return best_path
