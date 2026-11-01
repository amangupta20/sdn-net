#!/usr/bin/env python3
"""Automated evaluation for the Team 21 LB + security lab.

  E1  functional - ping matrix + client -> VIP through the load balancer
  E2  lb         - request spread + mean latency per algo
                   (round_robin vs least_conn vs weighted)
  E3  failover   - outage when the s1-s2 link is cut (sdn vs rstp [+ stp])
  E4  security   - UDP Packet-In flood from h_attacker: legit VIP traffic
                   with policing OFF vs ON (dropped floods, loss, REST stats)

Results land in results/results.json, results/summary.md and two charts.

  python3 sim/experiments.py                 # E1-E4 with rstp baseline
  python3 sim/experiments.py --with-stp      # also the ~30 s 802.1D baseline
  python3 sim/experiments.py --only lb
"""
import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mininet.clean import cleanup
from mininet.log import setLogLevel

from sim import topo
from net import config as cfg

RESULTS = os.path.join(ROOT, "results")
REST = f"http://127.0.0.1:{cfg.CONTROLLER_REST_PORT}/lb"

PING_TS = re.compile(r"\[(\d+\.\d+)\]")


def log(msg):
    print(f"\033[1;36m[exp]\033[0m {msg}", flush=True)


# ------------------------------------------------------------- controller
def start_controller():
    env = dict(os.environ, PYTHONPATH=ROOT)
    os.makedirs(RESULTS, exist_ok=True)
    # Append: several controllers run per evaluation (SDN phases + E4);
    # truncating would destroy the earlier phases' evidence on every rerun.
    logf = open(os.path.join(RESULTS, "controller.log"), "a")
    logf.write(f"\n===== controller start {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    logf.flush()
    proc = subprocess.Popen(
        ["ryu-manager",
         "--ofp-tcp-listen-port", str(cfg.OPENFLOW_PORT),
         "controller.app"],
        cwd=ROOT, env=env, stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", cfg.OPENFLOW_PORT), 0.2).close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("ryu-manager did not start; see results/controller.log")


def rest(path, body=None):
    req = urllib.request.Request(REST + path, method="PUT" if body else "GET",
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def wait_for_switches(n=3, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if len(rest("/topology")["connected"]) == n:
                time.sleep(0.5)  # let proactive host routes land
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


def wait_for_ping(net, src, dst, timeout=60):
    a, b = net.get(src), net.get(dst)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if re.search(r"1 received", a.cmd(f"ping -c1 -W1 {b.IP()}")):
            return True
        time.sleep(0.5)
    return False


# ------------------------------------------------------------------ E1/E2
# Backend servers auto-start with the topology (sim/topo.py); restart them
# here before measuring so every phase gets warm servers.
start_backends = topo.start_backends


def stop_backends(net):
    for srv in cfg.BACKENDS:
        net.get(srv).cmd("pkill -f 'http.server'")


def exp_functional(net):
    log("E1 functional: host ping matrix + client -> VIP")
    matrix = {}
    for a in cfg.HOSTS:
        for b in cfg.HOSTS:
            if a == b:
                continue
            out = net.get(a).cmd(f"ping -c1 -W1 {cfg.HOSTS[b]['ip']}")
            matrix[f"{a}->{b}"] = bool(re.search(r"1 received", out))
    ok = sum(matrix.values())
    log(f"    direct reachability {ok}/{len(matrix)}")
    vip_body = net.get("h_client").cmd(f"curl -s -m 4 http://{cfg.VIP}/").strip()
    vip_ok = vip_body in cfg.BACKENDS
    log(f"    client -> VIP answered by: {vip_body or '(nothing — backends up?)'}")
    return {"pairs": len(matrix), "reached": ok, "mismatches": [k for k, v in matrix.items() if not v],
            "vip_body": vip_body, "vip_ok": vip_ok, "paths": rest("/paths")}


def exp_lb(net, per_algo=30):
    log("E2 load balancing: spread + latency per algorithm")
    out = {}
    for algo in ("round_robin", "least_conn", "weighted"):
        rest("/policy", {"algo": algo})
        time.sleep(0.5)
        hits, lats = {}, []
        for _ in range(per_algo):
            t0 = time.time()
            body = net.get("h_client").cmd(f"curl -s -m 4 http://{cfg.VIP}/").strip()
            dt = (time.time() - t0) * 1000
            if body in cfg.BACKENDS:
                hits[body] = hits.get(body, 0) + 1
                lats.append(dt)
        stats = rest("/stats")
        out[algo] = {"hits": hits,
                     "mean_ms": round(statistics.mean(lats), 2) if lats else None,
                     "p99_ms": round(sorted(lats)[min(len(lats) - 1, int(len(lats) * 0.99))], 2) if lats else None,
                     "answered": sum(hits.values()),
                     "conns": stats["backends"]}
        log(f"    {algo:12s} {hits} mean={out[algo]['mean_ms']} ms")
    return out


# --------------------------------------------------------------------- E3
def cut_s1s2(net):
    link = net.linksBetween(net.get("s1"), net.get("s2"))[0]
    return link.intf1 if link.intf1.node.name == "s1" else link.intf2


def outage_trial(net, target=None, total=8.0, fail_at=2.5, interval=0.05):
    """Ping at 20 Hz, cut s1-s2 once, return the longest gap. Target is the
    VIP under SDN (the controller answers for it) but a real backend IP in
    standalone modes (no controller there to own the VIP)."""
    target = target or cfg.VIP
    client = net.get("h_client")
    intf = cut_s1s2(net)
    client.cmd("rm -f /tmp/vip-ping.txt")
    client.cmd(f"ping -D -i {interval} -W 1 -c {int(total / interval)} "
               f"{target} > /tmp/vip-ping.txt 2>&1 &")
    time.sleep(fail_at)
    t_fail = time.time()
    subprocess.run(["ip", "link", "set", "dev", intf.name, "down"], check=True)
    time.sleep(total - fail_at + 1.0)
    net.configLinkStatus("s1", "s2", "up")
    time.sleep(2)  # let the restored link settle before the next trial
    text = client.cmd("cat /tmp/vip-ping.txt")
    ts = [float(m.group(1)) for m in PING_TS.finditer(text)]
    m = re.search(r"(\d+) packets transmitted, (\d+) received", text)
    if len(ts) < 2:
        return {"outage_ms": None, "sent": int(m.group(1)) if m else None,
                "received": int(m.group(2)) if m else 0}
    gap = max(b - a for a, b in zip(ts, ts[1:])) * 1000
    return {"outage_ms": round(max(0.0, gap - interval * 1000), 1),
            "sent": int(m.group(1)), "received": int(m.group(2)),
            "gap_started_after_fail_ms": round((ts[0] - t_fail) * 1000, 1)}


def exp_failover_sdn(net, trials):
    runs = []
    for i in range(trials):
        r = outage_trial(net)
        runs.append(r)
        log(f"E3 failover [sdn restoration] trial {i + 1}/{trials}: "
            f"outage {r['outage_ms']} ms ({r['received']}/{r['sent']} pings back)")
    rec = [x["reprogram_ms"] for x in rest("/stats")["recoveries"]]
    return {"trials": runs, "reprogram_ms": rec}


def exp_failover_legacy(mode, trials):
    log(f"E3 failover [{mode}]: standalone OVS with {mode.upper()}")
    cleanup()
    net = topo.start(mode)
    try:
        t0 = time.time()
        if not wait_for_ping(net, "h_client", "srv1", timeout=120):
            return {"error": f"{mode} never converged"}
        converge = time.time() - t0
        log(f"    initial {mode} convergence {converge:.1f} s")
        runs = []
        for i in range(trials):
            time.sleep(4 if mode == "rstp" else 40)
            wait_for_ping(net, "h_client", "srv1")
            total = 8.0 if mode == "rstp" else 70.0
            r = outage_trial(net, target=cfg.HOSTS["srv1"]["ip"], total=total)
            runs.append(r)
            log(f"E3 failover [{mode}] trial {i + 1}/{trials}: outage {r['outage_ms']} ms")
            time.sleep(4 if mode == "rstp" else 45)
        return {"initial_convergence_s": round(converge, 1), "trials": runs}
    finally:
        net.stop()


# --------------------------------------------------------------------- E4
def exp_security(net, flood_s=6):
    """New-flow UDP flood at the VIP: a fresh socket per datagram means a
    fresh ephemeral source port, so every datagram is a table miss ->
    Packet-In (control-plane DDoS). Legit traffic = sequential client curls
    during the flood, from a different switch port (separate bucket)."""
    atk = net.get("h_attacker")
    out = {}
    for policing in (False, True):
        rest("/policy", {"policing": policing})
        before = rest("/stats")["limiter"]
        atk.cmd("pkill -f flood-vip.py; rm -f /tmp/flood.done")
        atk.cmd(f"cat > /tmp/flood-vip.py <<'EOF'\n"
                f"import socket, time\n"
                f"dst = '{cfg.VIP}'\n"
                f"t0 = time.time()\n"
                f"n = 0\n"
                f"while time.time() - t0 < {flood_s}:\n"
                f"    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                f"    try:\n"
                f"        s.sendto(b'x' * 64, (dst, 80))\n"
                f"    except OSError:\n"
                f"        pass\n"
                f"    finally:\n"
                f"        s.close()\n"
                f"    n += 1\n"
                f"open('/tmp/flood.done', 'w').write(str(n))\n"
                f"EOF")
        atk.cmd("nohup python3 /tmp/flood-vip.py >/tmp/flood.log 2>&1 &")
        time.sleep(0.5)
        hits, fails = 0, 0
        t0 = time.time()
        while time.time() - t0 < flood_s:
            body = net.get("h_client").cmd("curl -s -m 2 http://%s/" % cfg.VIP).strip()
            if body in cfg.BACKENDS:
                hits += 1
            else:
                fails += 1
        atk.cmd("pkill -f flood-vip.py")
        after = rest("/stats")["limiter"]
        out["policing_on" if policing else "policing_off"] = {
            "legit_ok": hits, "legit_fail": fails,
            "packetin_allowed": after["allowed"] - before["allowed"],
            "packetin_dropped": after["dropped"] - before["dropped"]}
        log(f"    E4 policing={'ON ' if policing else 'OFF'} legit ok={hits} fail={fails} "
            f"dropped={after['dropped'] - before['dropped']}")
        time.sleep(1)
    rest("/policy", {"policing": True})
    return out


# ------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--only", choices=["functional", "lb", "failover", "security"])
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--with-stp", action="store_true")
    args = p.parse_args()

    os.makedirs(RESULTS, exist_ok=True)
    setLogLevel("warning")
    cleanup()
    results = {}
    path = os.path.join(RESULTS, "results.json")
    if args.only and os.path.exists(path):
        with open(path) as f:
            results = json.load(f)
    results |= {"started": time.strftime("%Y-%m-%d %H:%M:%S")}

    def save():
        with open(path, "w") as f:
            json.dump(results, f, indent=2)

    ctrl = start_controller()
    net = None
    try:
        net = topo.start("sdn")
        log("waiting for all 3 switches on the remote controller")
        if not wait_for_switches():
            raise RuntimeError("controller never saw all 3 switches")
        if not wait_for_ping(net, "h_client", "srv1"):
            raise RuntimeError("client -> srv1 never came up")
        results["topology"] = rest("/topology")

        # Order matters: the E4 flood deliberately saturates the control
        # plane, so it runs last and cannot poison the other baselines.
        if args.only in (None, "functional"):
            start_backends(net)
            results["functional"] = exp_functional(net)
            save()
        if args.only in (None, "lb"):
            start_backends(net)
            results["lb"] = exp_lb(net)
            save()
        if args.only in (None, "failover"):
            start_backends(net)
            results["failover"] = {"sdn": exp_failover_sdn(net, args.trials)}
            save()
    finally:
        if net:
            try:
                stop_backends(net)
            except Exception:
                pass
            net.stop()
        ctrl.terminate()
        ctrl.wait()

    if args.only in (None, "failover"):
        # Standalone baselines need no controller; each is best-effort so a
        # slow STP convergence can never again void the finished SDN runs.
        try:
            results.setdefault("failover", {})["rstp"] = \
                exp_failover_legacy("rstp", args.trials)
        except Exception as e:
            log(f"    WARNING: rstp baseline failed ({e})")
            results.setdefault("failover", {})["rstp"] = {"error": str(e)}
        save()
        if args.with_stp:
            try:
                results["failover"]["stp"] = exp_failover_legacy("stp", 1)
            except Exception as e:
                log(f"    WARNING: stp baseline failed ({e})")
                results["failover"]["stp"] = {"error": str(e)}
            save()

    if args.only in (None, "security"):
        # Fresh controller + fabric: the storm gets a clean room and leaves
        # nothing behind that a later phase could trip over.
        ctrl = start_controller()
        net = None
        try:
            net = topo.start("sdn")
            if not wait_for_switches():
                raise RuntimeError("controller never saw all 3 switches")
            if not wait_for_ping(net, "h_client", "srv1"):
                raise RuntimeError("client -> srv1 never came up")
            start_backends(net)
            results["security"] = exp_security(net)
            save()
        finally:
            if net:
                try:
                    stop_backends(net)
                except Exception:
                    pass
                net.stop()
            ctrl.terminate()
            ctrl.wait()

    cleanup()
    save()
    log(f"wrote {path}")

    from sim import report
    report.render(results, RESULTS)


if __name__ == "__main__":
    main()
