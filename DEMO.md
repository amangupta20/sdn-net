# Demo runbook — Team 21 SDN lab (granular, step by step)

Total: ~13 minutes. Examiner sees: topology → remote controller → tests →
load balancing → algorithms → health → failover → security → numbers.
Each step below is: **GOAL → command → what you should see → what to say →
why it works** (the viva answer hidden inside the demo).

## Before demo day (once)

```bash
sudo ./run.sh build                        # image with Ryu + Mininet + OVS
python3 -m unittest discover -s tests      # 15/15, no Docker needed
# optional full sanity (takes ~6 min, rewrites results/):
sudo ./run.sh experiments --trials 1
```

## Terminal layout (3 windows + 1 browser)

| Window | Command | Role |
|---|---|---|
| T1 | `sudo ./run.sh controller` | Ryu remote controller (start first, leave running) |
| T2 | `sudo ./run.sh mininet` | the network + `mininet>` CLI |
| T3 | `sudo ./run.sh shell` | REST calls (`curl localhost:8080/…`) when you want CLI proof next to dashboard clicks |
| Browser | `http://localhost:8080/` | live dashboard (needs no internet — zero dependencies) |

Order matters: T1 before T2 (switches connect to the controller on boot).
Stop order at the end: `exit` in T2, Ctrl+C in T1.

---

## Phase 0 — start everything (≈2 min)

**T1:**
```bash
sudo ./run.sh controller
```
Expect (one line per switch):
```
switch s1 (dpid 1) connected; host routes installed
switch s2 (dpid 2) connected; host routes installed
switch s3 (dpid 3) connected; host routes installed
```
**Say:** *"This is our remote controller — one Ryu program. The three
switches boot in fail-secure mode, so right now they forward nothing; every
rule you will see today is installed from here."*

**T2:**
```bash
sudo ./run.sh mininet
```
Expect the host table (`h_client`/`h_attacker` on s1, `srv1–3` on s3,
`h_mon` on s2) and the `mininet>` prompt. Open the dashboard — it should
show all 3 switches connected and 3 alive backends.

**Why it works:** switches open an OpenFlow 1.3 session to `127.0.0.1:6653`;
on connect the controller wipes the tables and installs the base rules plus
one MAC route per known host over the live shortest path.

---

## Phase 1 — topology: what this network is (≈2 min, marks: topology + size)

**T2:**
```
mininet> nodes
mininet> net
```
Expect: `c0 h_attacker h_client h_mon s1 s2 s3 srv1 srv2 srv3`, then the
wiring — two hosts on s1, three servers + monitor across s2/s3, and the
`s1-s2-s3-s1` ring.

**Say:** *"Three OVS switches in a ring, six hosts. s1 is the edge with the
client and the attacker, s3 is the server farm, s2 carries the monitor. The
ring means every switch pair has a primary and a backup path — that is what
makes the failover demo possible. One virtual IP, 10.0.0.100, fronts the
three backends."*

Then prove the controller is **remote** (this is worth a full mark):
```
mininet> sh ovs-vsctl show | grep -B1 -A2 Controller
```
Expect: `Controller "tcp:127.0.0.1:6653" … is_connected: true`.
**Say:** *"Not a default in-process controller — a remote one, connected
over OpenFlow. Kill terminal 1 and this whole network goes dark."*

**Why no STP?** (they will ask): the controller answers every ARP itself
(proxy-ARP) and installs exact MAC paths, so nothing ever floods — and only
flooding can loop. No blocked links, no 30-second reconvergence.

## Phase 2 — testing: does it forward (≈2 min, marks: ping/pingall)

**T2:**
```
mininet> verify
```
Expect: a 31-row table, `31/31 checks reached` — every host pair plus
`h_client -> VIP answered by srvX`.

**Say:** *"This is the connectivity test from the criteria: the full ping
matrix plus one load-balanced request, all passing. Backend HTTP servers
auto-start so this works out of the box."*

Optional one-liner if they want the classic matrix: `pingall` (0% loss;
anything blocked would show as X — here nothing is, because isolation lives
at the VIP policy, not between users).

## Phase 3 — the load balancer core (≈3 min, the heart of Review-1)

**T2:**
```
mininet> h_client curl -s http://10.0.0.100/
mininet> h_client curl -s http://10.0.0.100/
mininet> h_client curl -s http://10.0.0.100/
```
Expect: `srv1`, `srv2`, `srv3` (order follows the active algorithm).

**Say:** *"One IP, three answers. The first packet of each connection is a
table miss, so the switch asks the controller; the controller scores the
backends and installs a NAT pair; every later packet of that connection is
rewritten and forwarded in the switch, at line rate, with no controller
involved."*

Now prove it — the flow table, twice (counters move):
```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```
Point at, top to bottom:
- `priority=900,arp actions=CONTROLLER` — ARP goes to the controller (proxy-ARP, no flood).
- `priority=200,tcp,…,tp_src=<ephemeral>,tp_dst=80 actions=set_field:…->eth_dst,set_field:…->ip_dst,output:2` — **the NAT pair**, one per connection, with `n_packets`/`n_bytes` counting. Run one more curl and dump again: the counters grew, no new PACKET_IN.
- `priority=100,dl_dst=… actions=output:N` — permanent MAC host routes (transit needs nothing per-flow; the rewritten MAC rides these).
- `priority=0 actions=CONTROLLER` — table-miss: unknown → ask the brain.

**Say:** *"Priority decides: exact connection match wins over the MAC
route, which wins over table-miss. That ordering is the whole design."*

## Phase 4 — algorithms + health, on the dashboard (≈2 min)

Dashboard → **LB algorithm** buttons: click `round_robin`, then
`least_conn`, then `weighted`. Repeat the curls each time.

**Say:** *"Round-robin is the static baseline — blind rotation. Least-conn
reads live flow counts. Weighted is our gap-filler: one lightweight score,
conns×10 + RTT + load×20, so a hot or laggy server sheds new connections.
Same traffic, different policy, no rewire — that programmability is the SDN
argument."* (T3 equivalent: `curl -X PUT localhost:8080/lb/policy -d
'{"algo":"least_conn"}'`.)

Dashboard → click the green `alive` pill on **srv2** (turns red), curl twice:
never `srv2`. Click again to revive.

**Say:** *"Health is a first-class signal. Marking a backend dead withdraws
its flows at once; new connections skip it. Production would add active
probes; here the health reporter is the operator — or the script."*
(T3 equivalent: `PUT /lb/health '{"srv2": false}'`, then `true`.)

## Phase 5 — failover: cut the cable live (≈2 min, marks: dynamic changes)

**T2:**
```
mininet> h_client ping -i 0.05 10.0.0.100 &
mininet> link s1 s2 down
```
Watch ~20 pings/s keep replying — via s3 now. Then:
```
mininet> h_client ping -c2 -W1 srv1
mininet> link s1 s2 up
```
(Pick the background job's `%1` and `kill %1`, or leave it and kill at the end.)

**Say:** *"We cut the primary bay uplink mid-flow and lost essentially
nothing — measured median 2.8 ms in our automated runs. What happens:
PORT_STATUS reaches the controller, paths are recomputed over the surviving
links, LB flows reinstall on demand. RSTP does ~2 ms too but needs spanning
tree; classic STP sits out ~30 seconds. Dashboard event feed shows the
reprogram entry; `/lb/stats` has the millisecond timings."*

**Why restoration, not groups?** One honest line: *"Protection groups flip
in-switch; we do controller restoration — detect, recompute, reinstall —
simpler to verify, and fast enough to match RSTP on this fabric."*

## Phase 6 — security: the flood, before/after (≈2 min, the Topic-13 payoff)

Setup (T3, or paste the flood into the attacker from T2 — E4's script does
exactly this): a UDP new-flow flood at the VIP from `h_attacker` while
curling legit traffic from `h_client`.

- Dashboard → policing **OFF**: legit curls die (0/4 in our runs) — and note
  the controller isn't even the bottleneck: the *switch* melts first.
- Dashboard → policing **ON**: flood packets die **in the OVS meter**
  (~200 pps cap on the attacker port), legit curls go 231/231, the
  *dropped* counter climbs by the tens of thousands.

**Say:** *"Two layers, mapping straight to the mitigation matrix: the meter
defends the dataplane, the per-port token bucket defends the controller.
Either alone is insufficient — that is the defence-in-depth point of slide
9, measured, not asserted."* Also show `/lb/stats` → `allowed` vs
`dropped`.

## Phase 7 — numbers to close (≈1 min)

Open `results/summary.md` (+ `lb.png`, `failover.png`):

| Experiment | Result |
|---|---|
| E1 functional | 30/30 pairs, VIP answers |
| E2 spread (30 curls × 3 algos) | 10/10/10 everywhere (~6 ms first-packet setup) |
| E3 cut s1–s2 | SDN restoration median 2.8 ms · RSTP 2.2 ms (5.1 s to converge) |
| E4 flood | OFF: 0/4 legit survive · ON: 231/231, ~25k flood pkts dropped |

**Closing line:** *"Open control is SDN's strength and its attack surface.
With every plane authenticated, metered and monitored, openness becomes the
advantage — fast patches, peer review — at under 10% overhead. That is the
whole thesis on one network."* (Future scope if asked: ML anomaly
detection on flow stats, blockchain-anchored flow integrity, quantum-safe
OpenFlow TLS.)

---

## If time is short (8-minute cut)

Keep phases 0→3, 5, and 7. Skip algorithm-switching detail (just name the
three), skip the RSTP/STP comparison table, skip reading `dump-flows`
line-by-line (show only the NAT pair line).

## If something breaks mid-demo

| Symptom | Rescue (say it out loud — recovery is also a demo) |
|---|---|
| `Waiting for switches` | T1 controller isn't up — start it first, then T2 |
| `verify` VIP FAIL | backend http servers — restart `mininet` (they auto-start) |
| port 6653 busy / half-built net | `sudo ./run.sh shell` → `mn -c` → `exit`, restart T1 |
| flood script still running | `h_attacker pkill -f flood-vip.py` |
| dashboard unreachable | controller (T1) down — restart it; switches reconnect by themselves |
| everything weird after the flood | flood melts the emulated fabric — `link s1 s2 up`, wait ~10 s for the reconcile poll, or restart T1+T2 clean |
