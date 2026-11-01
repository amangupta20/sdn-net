"""Unit tests for the pure decision modules (no Ryu / Mininet needed).

Run anywhere:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.policy import LoadBalancer, build_graph, out_port_for, shortest_path
from controller.security import RateLimiter
from net import config as cfg


class TestConfig(unittest.TestCase):
    def test_topology_size(self):
        # Criteria: correct hosts/switches/links + network size.
        self.assertEqual(len(cfg.SWITCHES), 3)
        self.assertEqual(len(cfg.HOSTS), 6)
        self.assertEqual(len(cfg.BACKBONE), 3)
        self.assertEqual(len(cfg.BACKENDS), 3)
        self.assertEqual(cfg.VIP, "10.0.0.100")

    def test_hosts_attached(self):
        for name, h in cfg.HOSTS.items():
            self.assertIn(h["sw"], cfg.SWITCHES)
        for be in cfg.BACKENDS:
            self.assertIn(be, cfg.HOSTS)

    def test_dpids_unique(self):
        dpids = [s["dpid"] for s in cfg.SWITCHES.values()]
        self.assertEqual(len(set(dpids)), 3)


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.g = build_graph(cfg.BACKBONE)

    def test_ring_paths(self):
        self.assertEqual(shortest_path(self.g, "s1", "s3"), ["s1", "s3"])
        self.assertEqual(shortest_path(self.g, "s1", "s2"), ["s1", "s2"])
        self.assertEqual(out_port_for(self.g, "s1", "s3"), 2)
        self.assertEqual(out_port_for(self.g, "s1", "s2"), 1)

    def test_failover_reroutes(self):
        g2 = build_graph(cfg.BACKBONE, down_links={("s1", "s2")})
        self.assertEqual(shortest_path(g2, "s1", "s2"), ["s1", "s3", "s2"])
        self.assertEqual(out_port_for(g2, "s1", "s2"), 2)

    def test_partition(self):
        g2 = build_graph(cfg.BACKBONE, down_links={("s1", "s2"), ("s1", "s3")})
        self.assertIsNone(shortest_path(g2, "s1", "s2"))


class TestLoadBalancer(unittest.TestCase):
    def test_round_robin_even(self):
        lb = LoadBalancer(["srv1", "srv2", "srv3"], algo="round_robin")
        picks = [lb.select() for _ in range(30)]
        for be in ("srv1", "srv2", "srv3"):
            self.assertEqual(picks.count(be), 10)

    def test_dead_backend_skipped(self):
        lb = LoadBalancer(["srv1", "srv2", "srv3"], algo="round_robin")
        lb.set_alive("srv2", False)
        picks = [lb.select() for _ in range(20)]
        self.assertNotIn("srv2", picks)
        self.assertEqual(picks.count("srv1"), 10)
        self.assertEqual(picks.count("srv3"), 10)

    def test_all_dead_raises(self):
        lb = LoadBalancer(["srv1", "srv2"], algo="weighted")
        lb.set_alive("srv1", False)
        lb.set_alive("srv2", False)
        with self.assertRaises(RuntimeError):
            lb.select()

    def test_least_conn_picks_idle(self):
        lb = LoadBalancer(["srv1", "srv2"], algo="least_conn")
        lb.set_stats("srv1", conns=5)
        lb.set_stats("srv2", conns=1)
        self.assertEqual(lb.select(), "srv2")

    def test_weighted_avoids_loaded(self):
        lb = LoadBalancer(["srv1", "srv2"], algo="weighted")
        lb.set_stats("srv1", conns=0, rtt_ms=50.0, load=0.9)
        lb.set_stats("srv2", conns=0, rtt_ms=1.0, load=0.1)
        self.assertEqual(lb.select(), "srv2")

    def test_bad_algo(self):
        with self.assertRaises(ValueError):
            LoadBalancer(["srv1"], algo="magic")


class TestRateLimiter(unittest.TestCase):
    def test_burst_then_police(self):
        rl = RateLimiter(rate_pps=10, burst=5, clock=lambda: 0.0)
        for _ in range(5):
            self.assertTrue(rl.allow("s1", now=0.0))
        self.assertFalse(rl.allow("s1", now=0.0))
        self.assertEqual(rl.dropped, 1)

    def test_refill(self):
        rl = RateLimiter(rate_pps=10, burst=5, clock=lambda: 0.0)
        for _ in range(5):
            rl.allow("s1", now=0.0)
        self.assertTrue(rl.allow("s1", now=1.0))  # +10 tokens
        snap = rl.snapshot()
        self.assertEqual(snap["allowed"], 6)
        self.assertEqual(snap["dropped"], 0)

    def test_per_switch_buckets(self):
        rl = RateLimiter(rate_pps=1, burst=1, clock=lambda: 0.0)
        self.assertTrue(rl.allow("s1", now=0.0))
        self.assertTrue(rl.allow("s2", now=0.0))
        self.assertFalse(rl.allow("s1", now=0.0))


if __name__ == "__main__":
    unittest.main()
