"""Single source of truth for the Team 21 lab network.

Both the Mininet topology (sim/topo.py) and the Ryu controller
(controller/app.py) import this module, so addresses, ports and the VIP can
never drift apart between the emulated network and the controller's view.

Topology (marks: 3 switches, 6 hosts, ring backbone):

                  c0 (Ryu REMOTE, 127.0.0.1:6653)
                  /      |       \\
              s1 ------- s2 ------- s3
              |                     |      + backup link s1--s3
        h_client, h_attacker    srv1, srv2, srv3, h_mon

  VIP 10.0.0.100 -> srv1-3 (L3/L4 NAT in the controller, Review-1 deck).
  h_attacker replays the security deck (Packet-In flood / spoofed flows).
  h_mon is the IDS/monitor host (Snort stand-in, tcpdump here).
"""

SWITCHES = {
    "s1": {"dpid": 1, "role": "Edge - clients + attacker"},
    "s2": {"dpid": 2, "role": "Core - transit + monitor"},
    "s3": {"dpid": 3, "role": "Farm - backend servers"},
}

# Ring: every switch pair has a primary and a backup path, so a single
# `link sX sY down` never partitions the network (failover demo).
# (switch_a, port_on_a, switch_b, port_on_b)
BACKBONE = [
    ("s1", 1, "s2", 1),
    ("s2", 2, "s3", 1),
    ("s3", 2, "s1", 2),
]

HOSTS = {
    "h_client":   {"ip": "10.0.0.10", "mac": "00:00:00:00:00:0a",
                   "sw": "s1", "port": 10, "kind": "LB client (curl/iperf)"},
    "h_attacker": {"ip": "10.0.0.99", "mac": "00:00:00:00:00:99",
                   "sw": "s1", "port": 11, "kind": "Attacker (flood/spoof)"},
    "srv1": {"ip": "10.0.0.11", "mac": "00:00:00:00:00:11",
             "sw": "s3", "port": 10, "kind": "Backend replica 1"},
    "srv2": {"ip": "10.0.0.12", "mac": "00:00:00:00:00:12",
             "sw": "s3", "port": 11, "kind": "Backend replica 2"},
    "srv3": {"ip": "10.0.0.13", "mac": "00:00:00:00:00:13",
             "sw": "s3", "port": 12, "kind": "Backend replica 3"},
    "h_mon": {"ip": "10.0.0.20", "mac": "00:00:00:00:00:20",
              "sw": "s2", "port": 10, "kind": "Monitor / IDS"},
}

BACKENDS = ["srv1", "srv2", "srv3"]

VIP = "10.0.0.100"
VIP_MAC = "02:00:00:00:00:fe"   # proxy-ARP answer for the VIP
VIP_TCP_PORT = 80               # backends serve HTTP on :80

# Link rates (the s2--s3 core link is the shared bottleneck LB balances over).
ACCESS_RATE = 10_000_000
BACKBONE_RATE = 100_000_000

# --------------------------------------------------------------------------
# Controller-side constants
# --------------------------------------------------------------------------
COOKIE_BASE = 0x1000   # table-miss, ARP, IPv6 drop
COOKIE_LB = 0x2001     # VIP NAT + per-hop LB forwarding flows
COOKIE_LEARN = 0x2002  # learned host-to-host flows
COOKIE_ACL = 0x3001    # security drops (reserved)

REACTIVE_IDLE_TIMEOUT = 30

CONTROLLER_REST_PORT = 8080
OPENFLOW_PORT = 6653

# Packet-In policing defaults (security deck: Packet-In DDoS defence).
# Token bucket per switch: RATE tokens/sec refill, BURST max burst.
POLICE_RATE_PPS = 200.0
POLICE_BURST = 100.0


def dpid_of(switch_name):
    return SWITCHES[switch_name]["dpid"]


def switch_by_dpid(dpid):
    for name, sw in SWITCHES.items():
        if sw["dpid"] == dpid:
            return name
    return None


def host_by_ip(ip):
    if ip == VIP:
        return "__vip__"
    for name, h in HOSTS.items():
        if h["ip"] == ip:
            return name
    return None


def port_map():
    """{(sw, port_no): (neighbour_sw_or_host, label)} for wiring checks."""
    m = {}
    for a, pa, b, pb in BACKBONE:
        m[(a, pa)] = (b, "backbone")
        m[(b, pb)] = (a, "backbone")
    for name, h in HOSTS.items():
        m[(h["sw"], h["port"])] = (name, "host")
    return m
