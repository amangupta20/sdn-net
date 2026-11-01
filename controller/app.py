"""Team 21 Ryu controller: L4 load balancer + security policing.

Serves the live demo dashboard at http://<host>:8080/ (controller/dashboard.html)
plus the JSON API under /lb/* consumed by the dashboard, curl and experiments.

One Ryu app (run: ryu-manager controller.app) so the demo has a single
REMOTE controller to point at. Wiring only — all decisions live in the
pure, unit-tested modules:

  controller/policy.py    backend selection (RR / least-conn / weighted),
                          stdlib BFS path computation over the live graph
  controller/security.py  per-switch Packet-In token bucket (anti-DDoS)

Behaviour:
  * Proxy-ARP for the VIP and all known hosts -> the ring never floods,
    so no Spanning Tree is needed (all links stay usable).
  * First packet of a client->VIP connection raises Packet-In; the
    controller picks a backend, installs a 5-tuple NAT flow pair on the
    ingress edge plus per-hop IP forwarding on transit/egress, and
    Packet-Outs the trigger packet. Later packets stay in the dataplane.
  * PORT_STATUS down/up updates the live graph, wipes LB flows (they are
    reinstalled on demand over the new shortest path) and records the
    controller reaction time (restoration demo).
  * Packet-In policing drops floods at the controller edge and counts them
    as security events (before/after comparison via PUT /lb/policy).
  * Backend health is REST-driven (PUT /lb/health): alive/dead plus load
    and RTT signals. Withdrawing a dead backend's flows is instant; new
    connections avoid it. (Production would add active probes; here the
    health reporter is the operator / experiments script, which keeps the
    controller single-threaded and deadlock-free.)
"""

import json
import logging
import os
import time

from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub, ofctl_v1_3
from ryu.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from controller import policy as lb_policy
from controller import security as sec_mod
from net import config as cfg

LOG = logging.getLogger("teamsdn.lbsec")
BASE = "/lb"


def _json(obj, status=200):
    return Response(status=status, content_type="application/json",
                    body=json.dumps(obj, indent=2, default=str).encode())


class LBSecController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.down_links = set()   # {(a, b)} sorted pairs currently failed
        self.graph = lb_policy.build_graph(cfg.BACKBONE)
        self.lb = lb_policy.LoadBalancer(cfg.BACKENDS, algo="weighted")
        self.limiter = sec_mod.RateLimiter(cfg.POLICE_RATE_PPS, cfg.POLICE_BURST)
        self.policing = True
        self.stats = {"packet_in": 0, "lb_flows": 0, "learn_flows": 0,
                        "dup_packetin": 0}
        # Connection stickiness: this kernel/OVS combo delivers the same
        # table-miss packet to the controller several times (~1 ms apart).
        # Treating each copy as a new connection installs conflicting NAT
        # flows (same match, different backends) and kills the connection.
        # Keying selection on the 5-tuple makes re-processing idempotent.
        self.conn_cache = {}  # (src,dst,proto,sp,dp) -> (backend, expiry)
        self.sec_events = []      # recent policing/withdrawal events
        self.recoveries = []      # controller reaction times after PORT_STATUS
        self.waiters = {}
        self.port_live = {}  # (sw, port_no) -> bool, from periodic polls
        kwargs["wsgi"].register(LBRest, {"app": self})
        self.monitor = hub.spawn(self._reconcile_loop)

    def _reconcile_loop(self):
        """Damping against spurious PORT_STATUS flaps: every 5 s, poll the
        real port state and heal any backbone link whose both ends are up.
        Fast reaction still comes from PORT_STATUS; this only repairs."""
        while True:
            hub.sleep(5)
            for dp in list(self.datapaths.values()):
                try:
                    dp.send_msg(dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0))
                except Exception:  # switch went away mid-poll; next round
                    pass

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        sw = cfg.switch_by_dpid(dp.id)
        if sw is None:
            return
        # Rebuild this switch's backbone liveness from scratch: a port
        # missing from the reply (deleted from the datapath) counts as
        # down, so a vanished port can never linger as stale-live.
        seen = set()
        for p in ev.msg.body:
            if self._neighbour_on_port(sw, p.port_no) is not None:
                seen.add(p.port_no)
                self.port_live[(sw, p.port_no)] = \
                    not (p.state & ofp.OFPPS_LINK_DOWN)
        for a, pa, b, pb in cfg.BACKBONE:
            if a == sw and pa not in seen:
                self.port_live[(a, pa)] = False
            if b == sw and pb not in seen:
                self.port_live[(b, pb)] = False
        for a, pa, b, pb in cfg.BACKBONE:
            pair = tuple(sorted((a, b)))
            if pair not in self.down_links:
                continue
            # Heal only when BOTH ends were recently seen up: a one-sided
            # poll can otherwise resurrect a truly dead link.
            if self.port_live.get((a, pa)) and self.port_live.get((b, pb)):
                self.down_links.discard(pair)
                self.graph = self._live_graph()
                self._reprogram_all()
                self._record(f"link recovered {a}:{pa} <-> {b}:{pb} (reconciled)")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        """Wakes the REST thread blocked in ofctl_v1_3.get_flow_stats."""
        msg = ev.msg
        pending = self.waiters.get(msg.datapath.id, {})
        if msg.xid not in pending:
            return
        lock, msgs = pending[msg.xid]
        msgs.append(msg)
        if msg.flags & msg.datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        del pending[msg.xid]
        lock.set()

    # ------------------------------------------------------------ helpers
    def _record(self, text):
        self.sec_events.append({"t": round(time.time(), 3), "event": text})
        del self.sec_events[:-50]
        LOG.info(text)

    def _live_graph(self):
        return lb_policy.build_graph(cfg.BACKBONE, self.down_links)

    def _neighbour_on_port(self, sw, port_no):
        for a, pa, b, pb in cfg.BACKBONE:
            if a == sw and pa == port_no:
                return b
            if b == sw and pb == port_no:
                return a
        return None

    # ------------------------------------------------------ switch connect
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        parser, ofp = dp.ofproto_parser, dp.ofproto
        sw = cfg.switch_by_dpid(dp.id)

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

        to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._set_edge_meter(dp, self.policing)
        self._add(dp, 0, parser.OFPMatch(), to_ctrl, cookie=cfg.COOKIE_BASE)
        self._add(dp, 900, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                  to_ctrl, cookie=cfg.COOKIE_BASE)
        self._add(dp, 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6),
                  [], cookie=cfg.COOKIE_BASE)
        self._program_host_routes(dp)
        LOG.info("switch %s (dpid %d) connected; host routes installed", sw, dp.id)

    def _program_host_routes(self, dp):
        """Proactive eth_dst forwarding for every known host over the live
        graph: local hosts go out the access port, remote hosts toward the
        first hop of the shortest path. Re-run on every topology change."""
        parser = dp.ofproto_parser
        dpid = dp.id
        sw = cfg.switch_by_dpid(dpid)
        graph = self._live_graph()
        for host, h in cfg.HOSTS.items():
            if h["sw"] == sw:
                out = h["port"]
            else:
                out = lb_policy.out_port_for(graph, sw, h["sw"])
                if out is None:
                    continue  # partitioned; fixed when the link returns
            self._add(dp, 100, parser.OFPMatch(eth_dst=h["mac"]),
                      [parser.OFPActionOutput(out)], cookie=cfg.COOKIE_LEARN)

    # ----------------------------------------- dataplane flood policing
    # OVS meter on the attacker's port: new-flow floods to the VIP are
    # dropped IN THE SWITCH above the rate, so they never become upcalls.
    # The token bucket (security.py) remains as the second layer for
    # distributed floods the meter cannot see.
    METER_ID = 1

    def _edge_attacker_port(self):
        h = cfg.HOSTS["h_attacker"]
        return h["sw"], h["port"]

    def _set_edge_meter(self, dp, enable):
        atk_sw, atk_port = self._edge_attacker_port()
        if cfg.switch_by_dpid(dp.id) != atk_sw:
            return
        parser, ofp = dp.ofproto_parser, dp.ofproto
        # Delete-then-add: idempotent across reconnects and rate changes
        # (deleting a missing meter just yields a harmless OFPT_ERROR).
        dp.send_msg(parser.OFPMeterMod(
            dp, command=ofp.OFPMC_DELETE, flags=ofp.OFPMF_PKTPS,
            meter_id=self.METER_ID, bands=[]))
        if enable:
            bands = [parser.OFPMeterBandDrop(
                rate=int(self.limiter.rate), burst_size=int(self.limiter.burst))]
            dp.send_msg(parser.OFPMeterMod(
                dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_PKTPS,
                meter_id=self.METER_ID, bands=bands))
            to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=950,
                cookie=cfg.COOKIE_ACL, idle_timeout=0,
                match=parser.OFPMatch(in_port=atk_port,
                                      eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_dst=cfg.VIP),
                instructions=[parser.OFPInstructionMeter(self.METER_ID),
                              parser.OFPInstructionActions(
                                  ofp.OFPIT_APPLY_ACTIONS, to_ctrl)]))
            LOG.info("edge meter on %s port %s: VIP floods above %s pps dropped",
                     atk_sw, atk_port, int(self.limiter.rate))
        else:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE, table_id=0,
                cookie=cfg.COOKIE_ACL, cookie_mask=0xFFFFFFFFFFFFFFFF,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

    def _reprogram_all(self):
        for dp in self.datapaths.values():
            if dp.id in [cfg.dpid_of(s) for s in cfg.SWITCHES]:
                self._program_host_routes(dp)

    def _wipe_lb_flows(self):
        for dp in self.datapaths.values():
            parser, ofp = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE, table_id=0,
                cookie=cfg.COOKIE_LB, cookie_mask=0xFFFFFFFFFFFFFFFF,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

    # ------------------------------------------------------ port status
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status(self, ev):
        t = time.time()
        msg, dp, ofp = ev.msg, ev.msg.datapath, ev.msg.datapath.ofproto
        port_no = msg.desc.port_no
        # Carrier state is authoritative. A DELETE with the link up is OVS
        # port churn (delete + imminent re-add), not a cable cut: acting on
        # it amputates healthy links. Only the LINK_DOWN bit means down.
        down = bool(msg.desc.state & ofp.OFPPS_LINK_DOWN)
        sw = cfg.switch_by_dpid(dp.id)
        nbr = self._neighbour_on_port(sw, port_no)
        if nbr is None:
            return  # host port; host routes already cover it
        pair = tuple(sorted((sw, nbr)))
        if down and pair not in self.down_links:
            self.down_links.add(pair)
            self.graph = self._live_graph()
            self._reprogram_all()
            self._wipe_lb_flows()  # reinstalled on demand over the new path
            ms = (time.time() - t) * 1000
            self.recoveries.append({"t": round(time.time(), 3),
                                    "reprogram_ms": round(ms, 2)})
            del self.recoveries[:-20]
            self._record(f"link down {sw}:{port_no} <-> {nbr}; "
                         f"paths recomputed in {ms:.2f} ms")
        elif not down and pair in self.down_links:
            if msg.reason == ofp.OFPPR_ADD or not (msg.desc.state & ofp.OFPPS_LINK_DOWN):
                self.down_links.discard(pair)
                self.graph = self._live_graph()
                self._reprogram_all()
                self._record(f"link up {sw}:{port_no} <-> {nbr}")

    # ----------------------------------------------------------- PACKET_IN
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        in_port = msg.match["in_port"]

        areq = pkt.get_protocol(arp.arp)
        if areq is not None and areq.opcode == arp.ARP_REQUEST:
            self._proxy_arp(dp, in_port, areq)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return
        self.stats["packet_in"] += 1

        if ip.dst == cfg.VIP:
            # Per-port bucket: the attacker's flood (port 11) is policed
            # without starving the legit client (port 10).
            if self.policing and not self.limiter.allow((dp.id, in_port)):
                if self.limiter.dropped % 50 == 1:
                    self._record(f"Packet-In policing: dropped flood "
                                 f"on s{dp.id} port {in_port} "
                                 f"(total {self.limiter.dropped})")
                return
            self._handle_vip(dp, in_port, msg, pkt, eth, ip)
        else:
            self._handle_host(dp, in_port, msg, eth, ip)

    # ------------------------------------------------------------ proxy ARP
    def _proxy_arp(self, dp, in_port, areq):
        if areq.dst_ip == cfg.VIP:
            mac = cfg.VIP_MAC
        else:
            target = cfg.host_by_ip(areq.dst_ip)
            if target is None or target == "__vip__":
                return
            mac = cfg.HOSTS[target]["mac"]
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP, dst=areq.src_mac, src=mac))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=mac, src_ip=areq.dst_ip,
            dst_mac=areq.src_mac, dst_ip=areq.src_ip))
        reply.serialize()
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)], data=reply.data))

    # ------------------------------------------------------- VIP / NAT load
    def _handle_vip(self, dp, in_port, msg, pkt, eth, ip):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ingress_sw = cfg.switch_by_dpid(dp.id)
        l4 = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
        pim = pkt.get_protocol(icmp.icmp)
        key = (ip.src, ip.dst, ip.proto, self._sport(l4, pim),
               self._dport(l4, pim, ip))
        now = time.time()
        hit = self.conn_cache.get(key)
        if hit is not None and hit[1] > now and \
                self.lb.backends[hit[0]].alive:
            backend = hit[0]  # duplicate upcall: same backend, no reselect
            self.stats["dup_packetin"] += 1
        else:
            try:
                backend = self.lb.select()
            except RuntimeError:
                LOG.warning("no backend alive; dropping %s -> VIP", ip.src)
                self._record("dropped client->VIP: no backend alive")
                return
            self.conn_cache[key] = (backend, now + cfg.REACTIVE_IDLE_TIMEOUT)
            if len(self.conn_cache) > 20000:  # flood cap: drop expired first
                self.conn_cache = {k: v for k, v in self.conn_cache.items()
                                     if v[1] > now}
                while len(self.conn_cache) > 15000:
                    self.conn_cache.pop(next(iter(self.conn_cache)))
        bconf = cfg.HOSTS[backend]
        graph = self._live_graph()
        path = lb_policy.shortest_path(graph, ingress_sw, bconf["sw"])
        if not path:
            self.lb.release(backend)
            LOG.warning("no path %s -> %s", ingress_sw, bconf["sw"])
            return

        match_fwd = dict(eth_type=ether_types.ETH_TYPE_IP,
                         ipv4_src=ip.src, ipv4_dst=cfg.VIP, ip_proto=ip.proto)
        match_rev = dict(eth_type=ether_types.ETH_TYPE_IP,
                         ipv4_src=bconf["ip"], ipv4_dst=ip.src, ip_proto=ip.proto)
        if isinstance(l4, tcp.tcp):
            match_fwd.update(tcp_src=l4.src_port, tcp_dst=l4.dst_port)
            match_rev.update(tcp_src=l4.dst_port, tcp_dst=l4.src_port)
        elif isinstance(l4, udp.udp):
            match_fwd.update(udp_src=l4.src_port, udp_dst=l4.dst_port)
            match_rev.update(udp_src=l4.dst_port, udp_dst=l4.src_port)

        # Per-hop ports along the path (first hop leaves the ingress switch).
        hops = []
        for i, sw in enumerate(path):
            if i == len(path) - 1:
                hops.append(bconf["port"])  # egress access port
            else:
                hops.append(graph[sw][path[i + 1]][0])

        # Ingress edge: 5-tuple NAT pair. Transit/egress need nothing extra:
        # the permanent dl_dst host routes (priority 100, installed at
        # switch connect) already forward by the rewritten MACs. Installing
        # per-flow transit rules here would race the PacketOut across switch
        # connections, so we deliberately do not.
        fwd_nat = [parser.OFPActionSetField(eth_dst=bconf["mac"]),
                   parser.OFPActionSetField(ipv4_dst=bconf["ip"]),
                   parser.OFPActionOutput(hops[0])]
        rev_nat = [parser.OFPActionSetField(eth_src=cfg.VIP_MAC),
                   parser.OFPActionSetField(ipv4_src=cfg.VIP),
                   parser.OFPActionOutput(in_port)]
        self._add(dp, 200, parser.OFPMatch(**match_fwd), fwd_nat,
                  cookie=cfg.COOKIE_LB, idle_timeout=cfg.REACTIVE_IDLE_TIMEOUT)
        self._add(dp, 200, parser.OFPMatch(**match_rev), rev_nat,
                  cookie=cfg.COOKIE_LB, idle_timeout=cfg.REACTIVE_IDLE_TIMEOUT)

        self.stats["lb_flows"] += 2
        LOG.info("VIP %s:%s -> %s via %s (algo=%s conns=%d ingress=s%s t=%.3f)",
                 ip.src, self._sport(l4, pim), backend, "->".join(path),
                 self.lb.algo, self.lb.backends[backend].conns, dp.id, time.time())

        # 3) Re-inject the trigger packet through the NAT actions.
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=fwd_nat, data=data))

    @staticmethod
    def _sport(l4, pim):
        if l4 is not None:
            return l4.src_port
        if pim is not None:
            return (pim.type, pim.code)
        return 0

    @staticmethod
    def _dport(l4, pim, ip):
        if l4 is not None:
            return l4.dst_port
        return 0

    # ------------------------------------------------- plain host traffic
    def _handle_host(self, dp, in_port, msg, eth, ip):
        """Non-VIP IPv4 (client<->mon, attacker probes...). Host routes are
        proactive, so this only fires for the first packet of a pair whose
        route was missing (partition healing); install the eth path."""
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dst = cfg.host_by_ip(ip.dst)
        if dst is None or dst == "__vip__":
            return
        src_sw = cfg.switch_by_dpid(dp.id)
        graph = self._live_graph()
        path = lb_policy.shortest_path(graph, src_sw, cfg.HOSTS[dst]["sw"])
        if not path:
            return
        hops = []
        for i, sw in enumerate(path):
            if i == len(path) - 1:
                hops.append(cfg.HOSTS[dst]["port"])
            else:
                hops.append(graph[sw][path[i + 1]][0])
        for sw, out in zip(path, hops):
            d = self.datapaths.get(cfg.dpid_of(sw))
            if d is None:
                continue
            p = d.ofproto_parser
            self._add(d, 120, p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                         ipv4_src=ip.src, ipv4_dst=ip.dst,
                                         ip_proto=ip.proto),
                      [p.OFPActionOutput(out)],
                      cookie=cfg.COOKIE_LEARN,
                      idle_timeout=cfg.REACTIVE_IDLE_TIMEOUT)
        self.stats["learn_flows"] += len(path)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=[parser.OFPActionOutput(hops[0])], data=data))

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _add(dp, priority, match, actions, cookie=0, idle_timeout=0):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] \
            if actions is not None else []
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=0, priority=priority, match=match,
            instructions=inst, cookie=cookie, idle_timeout=idle_timeout))


DASHBOARD = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "dashboard.html")


class LBRest(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.ctl = data["app"]

    @route("dash", "/", methods=["GET"])
    def index(self, req, **_):
        try:
            with open(DASHBOARD, "rb") as fh:
                body = fh.read()
        except OSError:
            body = (b"<h1>Team 21 lab</h1><p>dashboard.html missing; "
                    b"use <a href='/lb/stats'>/lb/stats</a></p>")
        return Response(content_type="text/html", body=body)

    @route("lb", BASE + "/topology", methods=["GET"])
    def topology(self, req, **_):
        links = [{"a": a, "pa": pa, "b": b, "pb": pb,
                  "down": tuple(sorted((a, b))) in self.ctl.down_links}
                 for a, pa, b, pb in cfg.BACKBONE]
        return _json({"switches": cfg.SWITCHES, "links": links,
                      "hosts": cfg.HOSTS, "vip": cfg.VIP,
                      "vip_mac": cfg.VIP_MAC, "backends": cfg.BACKENDS,
                      "connected": sorted(cfg.switch_by_dpid(d)
                                          for d in self.ctl.datapaths)})

    @route("lb", BASE + "/paths", methods=["GET"])
    def paths(self, req, **_):
        g = self.ctl._live_graph()
        out = {}
        for be in cfg.BACKENDS:
            dst = cfg.HOSTS[be]["sw"]
            for src in cfg.SWITCHES:
                p = lb_policy.shortest_path(g, src, dst)
                out[f"{src}->{be}"] = {
                    "path": p, "out_port": lb_policy.out_port_for(g, src, dst)}
        return _json(out)

    @route("lb", BASE + "/policy", methods=["GET"])
    def get_policy(self, req, **_):
        return _json({"algo": self.ctl.lb.algo, "algos": list(lb_policy.ALGOS),
                      "policing": self.ctl.policing,
                      "rate_pps": self.ctl.limiter.rate,
                      "burst": self.ctl.limiter.burst})

    @route("lb", BASE + "/policy", methods=["PUT"])
    def put_policy(self, req, **_):
        try:
            body = req.json if req.body else {}
            if "algo" in body:
                self.ctl.lb.set_algo(body["algo"])
            if "policing" in body:
                self.ctl.policing = bool(body["policing"])
                for dp in self.ctl.datapaths.values():
                    self.ctl._set_edge_meter(dp, self.ctl.policing)
            if "rate_pps" in body:
                self.ctl.limiter.rate = float(body["rate_pps"])
            if "burst" in body:
                self.ctl.limiter.burst = float(body["burst"])
            if "rate_pps" in body or "burst" in body:
                for dp in self.ctl.datapaths.values():
                    self.ctl._set_edge_meter(dp, self.ctl.policing)
        except (ValueError, TypeError) as e:
            return _json({"error": str(e)}, status=400)
        return self.get_policy(req)

    @route("lb", BASE + "/health", methods=["GET"])
    def get_health(self, req, **_):
        return _json({b: {"alive": s.alive, "conns": s.conns,
                          "rtt_ms": s.rtt_ms, "load": s.load,
                          "fails": s.fail_count}
                      for b, s in self.ctl.lb.backends.items()})

    @route("lb", BASE + "/health", methods=["PUT"])
    def put_health(self, req, **_):
        try:
            body = req.json if req.body else {}
            for be, val in body.items():
                if be not in self.ctl.lb.backends:
                    return _json({"error": f"unknown backend {be}"}, status=400)
                if isinstance(val, bool):
                    was = self.ctl.lb.backends[be].alive
                    self.ctl.lb.set_alive(be, val)
                    if was and not val:
                        self.ctl._wipe_lb_flows()
                        self.ctl._record(f"backend {be} marked dead; LB flows withdrawn")
                    elif not was and val:
                        self.ctl._record(f"backend {be} back alive")
                else:
                    st = val
                    self.ctl.lb.set_stats(
                        be, conns=st.get("conns"), rtt_ms=st.get("rtt_ms"),
                        load=st.get("load"))
                    if "alive" in st:
                        self.ctl.lb.set_alive(be, st["alive"])
        except (ValueError, TypeError, AttributeError) as e:
            return _json({"error": str(e)}, status=400)
        return self.get_health(req)

    @route("lb", BASE + "/stats", methods=["GET"])
    def stats(self, req, **_):
        c = self.ctl
        return _json({**c.stats, "limiter": c.limiter.snapshot(),
                      "backends": {b: {"alive": s.alive, "conns": s.conns}
                                   for b, s in c.lb.backends.items()},
                      "sec_events": c.sec_events[-20:],
                      "recoveries": c.recoveries[-20:]})

    @route("lb", BASE + "/flows/{dpid}", methods=["GET"])
    def flows(self, req, dpid, **_):
        dp = self.ctl.datapaths.get(int(dpid))
        if dp is None:
            return _json({"error": "unknown switch"}, status=404)
        return _json(ofctl_v1_3.get_flow_stats(dp, self.ctl.waiters))
