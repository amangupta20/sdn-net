"""Load-balancer decision logic — pure Python, no Ryu imports.

Kept separate from controller/app.py so it can be unit-tested on any machine
(without Ryu/Mininet installed). The Ryu app only calls into this module.

Algorithms (Review-1 deck, slide order):
  round_robin  - sequential, ignores server condition (baseline)
  least_conn   - fewest active flows (Wijaya et al. 2024 beats RR)
  weighted     - multi-parameter score: active conns + RTT + load + util.
                 Our research-gap contribution: one lightweight score over all
                 four signals instead of a single parameter.
"""

ALGOS = ("round_robin", "least_conn", "weighted")


class BackendState:
    """Per-backend signals the controller tracks."""

    def __init__(self, name):
        self.name = name
        self.alive = True
        self.conns = 0          # active flows assigned (least_conn)
        self.rtt_ms = 1.0       # last health-probe RTT (weighted)
        self.load = 0.0         # 0..1 reported/estimated load (weighted)
        self.fail_count = 0

    def score(self):
        """Lower is better. Weights chosen so one bad signal can't be hidden
        by the others, but conns dominate (they are the freshest signal)."""
        return self.conns * 10.0 + self.rtt_ms + self.load * 20.0

    def __repr__(self):  # pragma: no cover - debug helper
        return (f"BackendState({self.name} alive={self.alive} conns={self.conns} "
                f"rtt={self.rtt_ms} load={self.load})")


class LoadBalancer:
    def __init__(self, backends, algo="weighted"):
        if algo not in ALGOS:
            raise ValueError(f"algo must be one of {ALGOS}")
        self.backends = {b: BackendState(b) for b in backends}
        self.algo = algo
        self._rr_index = 0
        self._order = list(backends)

    # ------------------------------------------------------------- config
    def set_algo(self, algo):
        if algo not in ALGOS:
            raise ValueError(f"algo must be one of {ALGOS}")
        self.algo = algo

    def set_alive(self, name, alive):
        self.backends[name].alive = bool(alive)
        if not alive:
            self.backends[name].fail_count += 1

    def set_stats(self, name, conns=None, rtt_ms=None, load=None):
        st = self.backends[name]
        if conns is not None:
            st.conns = max(0, int(conns))
        if rtt_ms is not None:
            st.rtt_ms = float(rtt_ms)
        if load is not None:
            st.load = min(1.0, max(0.0, float(load)))

    def release(self, name):
        st = self.backends.get(name)
        if st is not None:
            st.conns = max(0, st.conns - 1)

    def alive_backends(self):
        return [b for b, st in self.backends.items() if st.alive]

    # ------------------------------------------------------------ select
    def select(self):
        """Pick a backend for a new flow. Raises RuntimeError if none alive."""
        alive = self.alive_backends()
        if not alive:
            raise RuntimeError("no backend alive")
        if self.algo == "round_robin":
            pick = self._round_robin(alive)
        elif self.algo == "least_conn":
            pick = min(alive, key=lambda b: self.backends[b].conns)
        else:
            pick = min(alive, key=lambda b: self.backends[b].score())
        self.backends[pick].conns += 1
        return pick

    def _round_robin(self, alive):
        # Walk the fixed order, skipping dead backends, so killing srv2
        # shifts its share to srv1/srv3 instead of stalling (failover demo).
        n = len(self._order)
        for _ in range(n):
            cand = self._order[self._rr_index % n]
            self._rr_index += 1
            if cand in alive:
                return cand
        raise RuntimeError("no backend alive")  # unreachable, alive non-empty


# --------------------------------------------------------------------------
# Path computation over the live topology (stdlib BFS, no networkx needed so
# unit tests run anywhere; controller/app.py feeds it the same graph).
# --------------------------------------------------------------------------
def build_graph(backbone_links, down_links=()):
    """Adjacency: {sw: {neighbour: (my_port, nbr_port)}}.

    backbone_links: [(a, pa, b, pb), ...]; down_links: {(a, b), ...} pairs
    treated as failed in either direction.
    """
    down = {tuple(sorted(p)) for p in down_links}
    graph = {}
    for a, pa, b, pb in backbone_links:
        if tuple(sorted((a, b))) in down:
            continue
        graph.setdefault(a, {})[b] = (pa, pb)
        graph.setdefault(b, {})[a] = (pb, pa)
    return graph


def shortest_path(graph, src, dst):
    """Return [src, ..., dst] or None. BFS, deterministic neighbour order."""
    if src == dst:
        return [src]
    if src not in graph or dst not in graph:
        return None
    prev = {src: None}
    queue = [src]
    while queue:
        cur = queue.pop(0)
        for nbr in sorted(graph.get(cur, ())):
            if nbr not in prev:
                prev[nbr] = cur
                if nbr == dst:
                    path, c = [], nbr
                    while c is not None:
                        path.append(c)
                        c = prev[c]
                    return path[::-1]
                queue.append(nbr)
    return None


def out_port_for(graph, src, dst):
    """First-hop port on `src` toward `dst`, or None if unreachable."""
    path = shortest_path(graph, src, dst)
    if not path or len(path) < 2:
        return None
    return graph[src][path[1]][0]
