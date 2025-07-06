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


class AdaptiveECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 2  # seconds

    def __init__(self, *args, **kwargs):
        super(AdaptiveECMP, self).__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.port_stats = {}
        self.datapaths = {}
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # FLOOD all unmatched packets (fallback for ping/arp)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        self.logger.info("[BOOT] Default FLOOD rule installed on switch %s", datapath.id)

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

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.STATS_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}
        self.logger.debug("[STATS] Port stats updated for switch %s", dpid)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return  # Ignore non-IP packets (e.g., ARP already handled by flood rule)

        dst_mac = eth.dst
        src_mac = eth.src

        self.logger.info("[PACKET_IN] sw:%s in_port:%s src:%s dst:%s", dpid, in_port, src_mac, dst_mac)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        dst_dpid = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                break
        

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
            match = parser.OFPMatch(eth_dst=dst_mac)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(mod)
            self.logger.info("[FLOW] Rule installed: sw=%s dst_mac=%s -> port %s", curr_sw, dst_mac, out_port)

        # Forward original packet immediately
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