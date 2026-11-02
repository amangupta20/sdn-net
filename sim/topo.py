#!/usr/bin/env python3
"""Mininet emulation of the Team 21 LB + security lab network.

                  c0 (Ryu REMOTE, 127.0.0.1:6653)
                  /      |       \\
              s1 ------- s2 ------- s3   (ring: s1-s2, s2-s3, s3-s1)
              |                       |
        h_client, h_attacker      srv1, srv2, srv3, h_mon

Modes:
  sdn   - OVS secure fail-mode, OpenFlow 1.3, Ryu controller/app.py
  rstp  - standalone OVS running RSTP (traditional failover baseline)
  stp   - standalone OVS running classic 802.1D STP (slow baseline)

Usage (inside the container, controller already running in another shell):
  python3 sim/topo.py              # sdn mode, drops into the Mininet CLI
  python3 sim/topo.py --mode rstp
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.clean import cleanup
from mininet.cli import CLI
from mininet.link import Link
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from net import config as cfg


def vsctl(*args):
    subprocess.run(["ovs-vsctl", *args], check=True, stdout=subprocess.DEVNULL)


def build(mode="sdn", controller_ip="127.0.0.1"):
    standalone = mode in ("rstp", "stp")
    net = Mininet(controller=None, switch=OVSSwitch, link=Link,
                  autoSetMacs=False, build=False)
    if not standalone:
        net.addController("c0", controller=RemoteController,
                          ip=controller_ip, port=cfg.OPENFLOW_PORT)
    for name, sw in cfg.SWITCHES.items():
        net.addSwitch(name, dpid=f"{sw['dpid']:016x}", protocols="OpenFlow13",
                      failMode="standalone" if standalone else "secure")
    for name, h in cfg.HOSTS.items():
        net.addHost(name, ip=h["ip"] + "/24", mac=h["mac"])
        net.addLink(name, h["sw"], port2=h["port"])
    for a, pa, b, pb in cfg.BACKBONE:
        net.addLink(a, b, port1=pa, port2=pb)
    net.build()
    return net


def enable_spanning_tree(net, mode):
    """Traditional baselines. s1 forced root so the blocked link is
    deterministic (s2--s3), matching the SDN primary paths."""
    for sw in net.switches:
        prio = 4096 if sw.name == "s1" else 32768
        if mode == "rstp":
            vsctl("set", "bridge", sw.name, "rstp_enable=true",
                  f"other_config:rstp-priority={prio}")
        else:
            vsctl("set", "bridge", sw.name, "stp_enable=true",
                  f"other_config:stp-priority={prio}")


def start(mode="sdn", controller_ip="127.0.0.1", with_backends=True):
    net = build(mode, controller_ip)
    net.start()
    if mode in ("rstp", "stp"):
        enable_spanning_tree(net, mode)
    for h in net.hosts:
        h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1")
    if with_backends:
        start_backends(net)
    return net


def start_backends(net):
    """Tiny HTTP server per backend answering its own name (LB target).
    Started automatically so the CLI demo and `verify` work out of the box;
    experiments.py restarts them the same way before measuring."""
    for srv in cfg.BACKENDS:
        h = net.get(srv)
        h.cmd(f"mkdir -p /tmp/www-{srv} && echo -n {srv} > /tmp/www-{srv}/index.html")
        h.cmd(f"pkill -f 'http.server.*{srv}'; nohup python3 -m http.server 80 "
              f"--directory /tmp/www-{srv} >/tmp/http-{srv}.log 2>&1 &")
    time.sleep(1)  # let the servers bind before the first curl/verify


def verify(net):
    """Connectivity matrix for the criteria sheet: every host pings every
    other host directly, plus client -> VIP through the load balancer."""
    info("\n    %-10s -> %-10s  %-8s %s\n" % ("from", "to", "actual", "result"))
    passed = total = 0
    pairs = [(a, b) for a in cfg.HOSTS for b in cfg.HOSTS if a != b]
    for a, b in pairs:
        out = net.get(a).cmd(f"ping -c 1 -W 1 {cfg.HOSTS[b]['ip']}")
        ok = " 0% packet loss" in out or " 0% packet loss," in out or \
            re.search(r"1 received", out) is not None
        passed += ok
        total += 1
        info("    %-10s -> %-10s  %-8s %s\n" % (
            a, b, "reached" if ok else "blocked", "PASS" if ok else "FAIL"))
    out = net.get("h_client").cmd(f"curl -s -m 3 http://{cfg.VIP}/")
    vip_ok = bool(out.strip())
    total += 1
    passed += vip_ok
    info("    %-10s -> %-10s  %-8s %s\n" % (
        "h_client", "VIP", "reached" if vip_ok else "blocked",
        "PASS" if vip_ok else "FAIL (start backend http servers?)"))
    info(f"\n    {passed}/{total} checks reached\n\n")


class LabCLI(CLI):
    def do_verify(self, _line):
        """Ping matrix + client -> VIP load-balancer check."""
        verify(self.mn)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["sdn", "rstp", "stp"], default="sdn")
    p.add_argument("--controller", default="127.0.0.1")
    args = p.parse_args()

    setLogLevel("info")
    cleanup()  # wipe interfaces/bridges from any crashed earlier run
    net = start(args.mode, args.controller)
    info("\n*** Team 21 hosts (VIP %s -> %s)\n" % (cfg.VIP, ", ".join(cfg.BACKENDS)))
    for name, h in cfg.HOSTS.items():
        info("    %-10s %-11s on %s port %-3d %s\n" %
             (name, h["ip"], h["sw"], h["port"], h["kind"]))
    info("\n*** Try:  verify                                     (marks: testing)\n"
         "          h_client ping -c3 %s                  (via load balancer)\n"
         "          h_client curl -s http://%s/               (which backend?)\n"
         "          link s1 s2 down                         (failover while pinging)\n"
         "          sh ovs-ofctl -O OpenFlow13 dump-flows s1 (NAT + host routes)\n"
         "          h_client ping -i 0.01 -c100 %s &         (background load)\n\n"
         % (cfg.VIP, cfg.VIP, cfg.VIP))
    LabCLI(net)
    net.stop()


if __name__ == "__main__":
    main()
