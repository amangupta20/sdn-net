"""Packet-In policing — pure Python, no Ryu imports (unit-testable).

Security deck, threat #1: Packet-In DDoS. A compromised host floods the
switch with table-miss packets; each one becomes a Packet-In and the
controller (single, central) saturates before the data plane does.

Defence: per-switch token bucket. Sustained rate above RATE_PPS gets dropped
at the controller edge and counted as an attack event; legitimate low-rate
flows (first packet of each real connection) still get through.

This is the "rate-limit + Packet-In policing" cell of the mitigation matrix
(slide 10). Controller clustering (the second half of that cell) is
documented in explanation.md as the production follow-up.
"""

import time


class RateLimiter:
    """Token bucket per key (here: per DPID)."""

    def __init__(self, rate_pps, burst, clock=None):
        self.rate = float(rate_pps)
        self.burst = float(burst)
        self._clock = clock or time.time
        self._buckets = {}   # key -> [tokens, last_timestamp]
        self.allowed = 0
        self.dropped = 0

    def allow(self, key="default", now=None):
        """True if this Packet-In may be processed, False if policed."""
        t = self._clock() if now is None else now
        tokens, last = self._buckets.get(key, (self.burst, t))
        tokens = min(self.burst, tokens + (t - last) * self.rate)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, t)
            self.allowed += 1
            return True
        self._buckets[key] = (tokens, t)
        self.dropped += 1
        return False

    def reset(self, key=None):
        if key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(key, None)

    def snapshot(self):
        return {"rate_pps": self.rate, "burst": self.burst,
                "allowed": self.allowed, "dropped": self.dropped}
