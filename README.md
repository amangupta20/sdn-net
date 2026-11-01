# Team 21 — SDN L4 Load Balancer + Security (Mininet + Ryu)

One remote-controller lab that covers **both** of our decks:

| Deck | What this repo demonstrates |
|---|---|
| **L4 Server Load Balancer** (Review-1) | One virtual IP fronts 3 backends; the controller picks a backend per connection (Round-Robin / Least-Connections / weighted score) and installs NAT flows. Health withdrawal, `curl`/`iperf` evaluation. |
| **Security Challenges in Open-Source SDN** (Topic-13) | Packet-In flood defence in **two layers** (OVS dataplane meter + controller token bucket), proxy-ARP (no flood, no STP), fail-closed switches, flow timeouts, RBAC-style REST health. Threat → countermeasure matrix included. |

**Result snapshot (measured, `results/`):** reachability 30/30 · LB spread 10/10/10 on every algorithm · link-cut outage SDN ~2.8 ms vs RSTP ~2.2 ms (5.1 s to converge) · flood OFF: 0/4 legit curls survive, ON: 231/231 survive with ~25k flood packets dropped.

## 1. The 30-second picture

```
                  c0 (Ryu REMOTE controller, 127.0.0.1:6653)
                  /      |       \\
              s1 ------- s2 ------- s3   (ring: every pair has a backup path)
              |                       |
     h_client, h_attacker        srv1, srv2, srv3, h_mon

VIP 10.0.0.100 ──NAT in s1──▶ srv1-3 (10.0.0.11–13, port 80)
h_attacker replays the security deck (UDP new-flow flood at the VIP).
h_mon is the IDS/monitor host.
```

A client curls **one IP** (`10.0.0.100`). The first packet of each connection
reaches the controller, which scores the backends and installs a NAT pair on
the ingress switch; everything after that stays in the switch dataplane.
Kill a backend or cut a cable and the next connection just goes elsewhere —
watch it happen live (see §4).

## 2. What you look at (4 surfaces, pick any)

| Surface | How | What the examiner sees |
|---|---|---|
| **Dashboard** ⭐ start here | `run.sh controller`, then open **http://localhost:8080/** | Live backend cards (kill/revive with a click), algorithm buttons, policing toggle + drop counters, routes, event feed. This is the "controller's brain" on screen. |
| **Mininet CLI** | `run.sh mininet` → `nodes`, `net`, `verify`, `pingall`, `link s1 s2 down/up` | Topology, connectivity tests, dynamic switch/link changes (the marks!). Backend HTTP servers auto-start, so `verify` passes out of the box (31/31). |
| **REST** (`/lb/*`) | `curl localhost:8080/lb/stats` etc. | Topology, paths, policy, health, per-switch flow tables. The dashboard is just a skin over this. |
| **Results** | `run.sh experiments` → `results/summary.md` + `lb.png` + `failover.png` | The before/after numbers for the report and viva. |

## 3. Quickstart

Needs: Linux + Docker (the container needs the host `openvswitch` kernel
module). On macOS run it inside an Ubuntu VM — see `MACOS.md`.

```bash
sudo ./run.sh build          # once (~5 min, builds Ryu/Mininet image)
python3 -m unittest discover -s tests     # 15 unit tests, no Docker needed

sudo ./run.sh controller     # terminal 1: Ryu (leave it running)
sudo ./run.sh mininet        # terminal 2: the network + Mininet CLI
# → open http://localhost:8080/ in a browser (terminal 3, optional)

sudo ./run.sh experiments --trials 3                  # full eval, ~6 min
sudo ./run.sh experiments --only lb                   # re-run one experiment
sudo ./run.sh shell          # helper shell inside the demo container
sudo ./run.sh stop           # stop everything
```

One project at a time — everything shares OpenFlow port 6653. In Mininet,
`exit` quits; Ctrl+C the controller when done.

> No sudo / Docker permission trick: `chmod 666 /var/run/docker.sock`
> (resets on reboot; the permanent version is adding yourself to the
> `docker` group). `run.sh` skips `sudo` automatically once `docker info`
> works.

## 4. The demo script (10 minutes, with expected outputs)

Terminal 1: `sudo ./run.sh controller` — wait for 3 connects.
Terminal 2: `sudo ./run.sh mininet`. Browser: `http://localhost:8080/`.

| # | Command (terminal 2 unless noted) | What to say | Expect |
|---|---|---|---|
| 1 | `nodes` / `net` | "3 switches in a ring, 6 hosts; s1 edge, s2 core, s3 farm." | 6 hosts, 3 switches, ring links |
| 2 | `verify` | "The connectivity test: full ping matrix plus client→VIP." | **31/31 checks reached** |
| 3 | `h_client curl -s http://10.0.0.100/` (×3) | "One IP, three answers — the controller spreads connections." | `srv1`, `srv2`, `srv3` |
| 4 | Dashboard → click **srv2** to kill it; repeat curl | "Health signal withdrawn; new flows skip the dead backend." | never `srv2`; click again to revive |
| 5 | Dashboard → switch algorithm RR → Least-Conn → Weighted | "Same traffic, different policy — live, no rewire." | button highlights, spread stays even |
| 6 | `sh ovs-ofctl -O OpenFlow13 dump-flows s1` | "Priority-200 NAT pair per connection, priority-100 MAC host routes, priority-0 table-miss to the controller." | `set_field … -> ip_dst` lines |
| 7 | `h_client ping -i 0.05 10.0.0.100 &` then `link s1 s2 down` | "Cutting the primary while traffic flows — watch it reroute via s3." | pings continue; `link s1 s2 up` after |
| 8 | Dashboard → policing OFF, flood from attacker; then ON | "Unprotected: legit curls die. Protected: flood dies in the switch meter, legit passes 231/231." | counters + E4 table in `results/` |
| 9 | `results/summary.md`, `lb.png`, `failover.png` | "Automated before/after: spread, outage, flood." | the numbers in §0 |

Viva one-liners live in `explanation.md` Part E (SDN, PACKET_IN, priorities,
proxy-ARP vs STP, fast-failover vs restoration, DSCP, Docker-why, "are the
timings real").

## 5. How it works (for the curious; skippable before a demo)

- **Proxy-ARP + permanent MAC routes.** The controller answers all ARP
  itself and pre-installs `eth_dst → port` routes (shortest path, recomputed
  on every topology change). Nothing ever floods, so the ring needs no
  Spanning Tree and every link stays usable.
- **VIP NAT per connection.** First packet client→VIP → PACKET_IN →
  backend chosen by `round_robin` / `least_conn` /
  `weighted = min(conns×10 + RTT + load×20)` → 5-tuple NAT pair on the
  ingress edge (`ip_dst`/`eth_dst` rewrite out, reverse on the way back,
  `idle_timeout 30 s`). Transit needs nothing extra — the rewritten MACs
  ride the permanent routes. (This also dodged a real bug: installing
  per-flow transit rules races the reinjected packet across switches.)
- **Security, two layers.** An **OVS meter** on the attacker port drops VIP
  floods above ~200 pps *in the switch* (protects the dataplane); a
  **per-port token bucket** at the controller edge (protects the control
  plane). `failMode=secure` = no controller, no forwarding (fail-closed).
  Backend health is REST-driven; a dead backend's flows are withdrawn
  instantly. Connection state is keyed by 5-tuple so duplicate upcalls
  (which this OVS/kernel combo emits) converge instead of conflicting.
- **Failover = restoration.** `PORT_STATUS` down → recompute shortest paths,
  reinstall host routes, wipe LB flows (reinstalled on demand over the new
  path), record the reaction time. A 5 s port-desc poll heals anything
  spurious. Only the LINK_DOWN carrier bit counts — OVS DELETE churn is
  ignored (trusting it once amputated the whole ring in testing).

## 6. Repo map

```
net/config.py            single source of truth: switches, hosts, VIP, ring, ports
controller/policy.py     backend selection + BFS paths (pure Python, unit-tested)
controller/security.py   Packet-In token bucket (pure Python, unit-tested)
controller/app.py        the Ryu app: proxy-ARP, NAT, restoration, REST /lb/*, dashboard
controller/dashboard.html live UI served by the controller at http://…:8080/
sim/topo.py              Mininet ring + auto-started backends + `verify` command
sim/experiments.py       E1 ping/VIP · E2 spread/latency · E3 cut (sdn/rstp[/stp]) · E4 flood
sim/report.py            results/summary.md + lb.png + failover.png
tests/                   15 unit tests (run anywhere, no Docker/Mininet/Ryu)
results/                 measured output (committed so the report is readable offline)
run.sh                   build | controller | mininet [sdn|rstp|stp] | experiments | shell | stop
```

## 7. Results (from the last full run)

See `results/summary.md`. Headlines: E1 30/30; E2 10/10/10 per algo
(~6 ms first-packet setup); E3 SDN restoration median 2.8 ms vs RSTP
2.2 ms (RSTP takes 5.1 s to converge first); E4 OFF 0/4 legit survive, ON
231/231 with ~25k flood packets dropped in-switch. Emulated timings on one
host — compare schemes against each other, not against hardware.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Waiting for switches` hangs | controller (terminal 1) not running — start it first |
| `verify` VIP FAIL | backend http servers (auto-started; if you killed them, restart `mininet`) |
| port 6653 busy / half-built net | Ctrl+C the old controller, `sudo ./run.sh shell` → `mn -c` → `exit` |
| `Error setting resource limits` | harmless Mininet-in-Docker warning |
| STP numbers wanted | `sudo ./run.sh experiments --with-stp` (adds ~2 min) |

---
Team 21 — Adithya M Dave · Aman Gupta · 21CSE456T Software Defined Networks.
Decks: *L4 Server Load Balancer* (Review-1) + *Security Challenges in Open-Source SDN* (Topic-13).
