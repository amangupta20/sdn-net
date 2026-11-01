# Team 21 lab — complete explanation and demo guide

Two decks, one network. The **Load Balancer** deck says: one VIP, controller
picks the backend per flow using server/network signals. The **Security**
deck says: the same centralisation opens a control-plane attack surface, so
every plane gets a defence. This file is the viva cheat sheet plus the exact
demo commands.

## Part A — background (60 seconds)

**SDN:** the control plane (decisions) moves into one program — the
controller — and switches (data plane) just follow flow rules installed over
**OpenFlow 1.3**. First packet of an unknown flow → **PACKET_IN** to the
controller → controller installs rules (**FLOW_MOD**) → later packets stay
in the switch. Our switches use `failMode=secure`: with no controller they
forward **nothing**, which proves every forwarding decision is the
controller's.

**Our topology:** 3 OVS switches in a **ring** (s1 edge, s2 core, s3 farm),
6 hosts: `h_client` + `h_attacker` on s1; `srv1-3` + `h_mon` on s2/s3.
One virtual IP `10.0.0.100` fronts the 3 backends (port 80).

## Part B — load balancer (Review-1 deck)

**VIP → backend NAT.** The controller answers ARP for the VIP with a virtual
MAC (`proxy-ARP`, so the ring never floods and needs no STP). The first
packet of each client→VIP connection raises a PACKET_IN; the controller
picks a backend and installs a **5-tuple NAT pair on the ingress edge**:

```
forward:  ip_src=client, ip_dst=VIP      -> set dst srvX IP/MAC, output next-hop
reverse:  ip_src=srvX,   ip_dst=client   -> set src VIP IP/MAC,  output client-port
```

Transit/egress switches get per-host-pair IP forwarding both directions.
Entries idle out after 30 s, so dead-backend state can't linger.

**Algorithms** (switch live: `PUT /lb/policy {"algo": ...}`):

| Algo | Rule | Deck reference |
|---|---|---|
| `round_robin` | sequential, ignores load | static baseline |
| `least_conn` | fewest assigned flows | Wijaya et al. 2024 |
| `weighted` | min(conns×10 + RTT + load×20) | our multi-parameter gap-filler |

**Failover & health.** `PUT /lb/health {"srv2": false}` withdraws all LB
flows at once; new connections skip srv2. A `PORT_STATUS` link-down does the
same for paths: host routes are recomputed over the surviving ring links and
LB flows are reinstalled on demand (controller **restoration**, ~ms, vs
RSTP seconds / STP ~30 s — measured in E3).

## Part C — security (Topic-13 deck, threat → fix)

| # | Threat (slide 7) | Our fix (slides 9–10) | Where to point |
| 1 | Packet-In DDoS | **two layers:** OVS meter on the attacker port drops VIP floods *in the switch* above 200 pps (`_set_edge_meter`), plus a per-port token bucket at the controller edge (`security.py`) for what gets through | E4: OFF → 0/4 legit curls survive; ON → 231/231 survive, ~25k flood packets dropped. Controller-side policing alone is NOT enough — the emulated switch melts first. That observation is the point. |
| 2 | Missing TLS/auth | documented: mutual-TLS on OpenFlow + RBAC token on REST (lab runs plaintext so Wireshark can *show* the MITM window) | `explanation` + Wireshark on `h_mon` |
| 3 | OpenFlow MITM | proxy-ARP + exact-match flows; no broadcast to hijack | `dump-flows` has no flood rule |
| 4 | Rogue SDN app | single controller image; flow cookies allowlisted (`0x2001`); REST health is operator-only | `app.py` + `COOKIE_LB` |
| 5 | Flow-table exhaustion | `idle_timeout=30` on every reactive flow | `dump-flows` durations |
| 6 | Switch spoofing | DPID allowlist = the 3 in `net/config.py`; unknown DPIDs get no host routes | `/lb/topology` connected list |

## Part D — demo commands (marks in brackets)

```bash
sudo ./run.sh controller     # terminal 1 (wait for 3 connects)
sudo ./run.sh mininet        # terminal 2
```

```
net                                     # [topology] ring + 6 attachments
nodes
verify                                  # [testing] ping matrix + client->VIP
h_client curl -s http://10.0.0.100/     # repeat: srv1/srv2/srv3 rotate
sh ovs-ofctl -O OpenFlow13 dump-flows s1  # NAT pair (priority 200) + host routes
h_client ping -i 0.05 10.0.0.100 &      # background VIP flow...
link s1 s2 down                         # [dynamic] ...reroutes via s3, ~0 loss
link s1 s2 up
```

Third shell (`sudo ./run.sh shell`):

```bash
curl -s -X PUT localhost:8080/lb/policy -d '{"algo":"least_conn"}'
curl -s localhost:8080/lb/stats         # conns per backend, drops, recoveries
curl -s -X PUT localhost:8080/lb/health -d '{"srv2": false}'
# h_client curl -s http://10.0.0.100/   # never srv2 now
curl -s -X PUT localhost:8080/lb/health -d '{"srv2": true}'
curl -s localhost:8080/lb/paths         # primary out-port per switch->backend
```

`results/summary.md` + `lb.png` + `failover.png` are the printouts for
"interpretation of results".

## Part E — viva cheat sheet

**Q: What is SDN?** Control/data-plane split; one controller programs dumb
switches via OpenFlow. **Q: First ping slower?** PACKET_IN → FLOW_MOD round
trip; later packets hit cached rules. **Q: Priorities?** Highest wins: ARP
900 > NAT 200 > host routes 100 > miss 0. **Q: Why no STP?** Proxy-ARP +
exact paths ⇒ nothing ever floods ⇒ loops are harmless. **Q: RR vs
least-conn vs weighted?** Blind rotation vs live conns vs conns+RTT+load
score. **Q: Failover time?** Restoration = detect (PORT_STATUS) + recompute
+ reinstall on next packet; RSTP reconverges the tree; STP waits 30 s.
**Q: Flood defence cost?** Token bucket drops only excess PACKET_INs;
legit first-packets still pass; counters prove it (`allowed` vs `dropped`).
**Q: Are timings real?** Emulated on one host — valid for comparing schemes,
not hardware claims. Measured here: SDN restoration ~2.8 ms median, RSTP ~2.2 ms, ~6 ms per first-packet setup. **Q: `Error setting resource limits`?** Harmless
Mininet-in-Docker warning.

**Q: Why does the controller cache connections (sticky selection)?** Our OVS/kernel combo delivers the same table-miss packet to the controller up to 3x (~1 ms apart). Treating each copy as a new connection installs conflicting NAT flows (same match, different backends) and the ACK lands on a backend that never saw the SYN, so it RSTs. Keying selection on the 5-tuple makes re-processing idempotent: duplicates converge instead of conflicting.

**Q: PORT_STATUS DELETE — link down?** No. OVS sends DELETE during port churn with the carrier still up. Only the LINK_DOWN bit means a cut; DELETEs are ignored, and a 5 s port-desc poll reconciles anything that disagrees. Blindly trusting DELETE amputated all three ring links in testing.

**Q: What if there is no controller?** Switches are `failMode=secure`: they forward nothing. Verified live: no controller, no VIP, no pings. Every forwarding decision provably comes from the controller.

## Part F — troubleshooting

| Symptom | Fix |
|---|---|
| `Waiting for switches` hangs | controller not running / wrong app; restart terminal 1 first |
| `pingall` all X / VIP empty | backends' `http.server` not started (E1/CLI needs them for curl; ping still works) |
| port 6653 in use | another controller running; Ctrl+C it |
| flood script lingers | `h_attacker pkill -f flood-vip.py` |
| mininet crashed dirty | `sudo ./run.sh shell`, then `mn -c`, `exit` |
| want STP numbers | `sudo ./run.sh experiments --with-stp` (~extra 2 min) |
