#!/usr/bin/env python3
"""Render results/results.json -> summary.md, lb.png, failover.png.

Matplotlib only (Agg backend): no Mininet, no Ryu, runs anywhere.
"""
import json
import os

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_PLT = True
except ImportError:  # host without the Docker image: text summary still works
    HAVE_PLT = False

from net import config as cfg


def _med(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    m = len(xs) // 2
    return (xs[m - 1] + xs[m]) / 2 if len(xs) % 2 == 0 else xs[m]


def render(results, outdir):
    os.makedirs(outdir, exist_ok=True)
    _chart_lb(results, os.path.join(outdir, "lb.png"))
    _chart_failover(results, os.path.join(outdir, "failover.png"))
    md = _markdown(results)
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write(md)
    print(f"[report] wrote summary.md, lb.png, failover.png in {outdir}")
    return md


def _chart_lb(results, path):
    if not HAVE_PLT:
        return
    lb = results.get("lb")
    if not lb:
        return
    algos = [a for a in ("round_robin", "least_conn", "weighted") if a in lb]
    if not algos:
        return
    fig, ax = plt.subplots()
    x = range(len(algos))
    width = 0.22
    for i, be in enumerate(cfg.BACKENDS):
        vals = [lb[a].get("hits", {}).get(be, 0) for a in algos]
        ax.bar([p + (i - 1) * width for p in x], vals, width, label=be)
    ax.set_xticks(list(x))
    ax.set_xticklabels(algos, rotation=10)
    ax.set_ylabel("requests answered")
    ax.set_title("VIP request spread per algorithm")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _chart_failover(results, path):
    if not HAVE_PLT:
        return
    fo = results.get("failover")
    if not fo:
        return
    labels, vals = [], []
    for key, name in (("sdn", "SDN restoration"), ("rstp", "RSTP"), ("stp", "STP")):
        sec = fo.get(key)
        if not sec or "trials" not in sec:
            continue
        med = _med([t.get("outage_ms") for t in sec["trials"]])
        if med is None:
            continue
        labels.append(name)
        vals.append(med / 1000.0)
    if not labels:
        return
    fig, ax = plt.subplots()
    ax.bar(labels, vals)
    ax.set_ylabel("median outage (s, log scale)")
    ax.set_yscale("log")
    ax.set_title("Link-cut outage: SDN vs spanning tree")
    for l, v in zip(labels, vals):
        ax.text(l, v, f" {v:.2f}s", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _markdown(results):
    L = ["# Team 21 lab - evaluation results", ""]
    L.append(f"Run started {results.get('started', '?')}. Emulated timings on one host: "
             "compare schemes against each other, not against hardware.")
    L.append("")
    f = results.get("functional")
    if f:
        L.append("## E1 Functional")
        L.append("")
        L.append(f"- Direct reachability: **{f['reached']}/{f['pairs']}** host pairs.")
        if f.get("mismatches"):
            L.append(f"- Unreachable: {', '.join(f['mismatches'])}")
        L.append(f"- client -> VIP answered by backend: **{f.get('vip_body', '?')}** "
                 f"({'OK' if f.get('vip_ok') else 'FAIL'}).")
        L.append("")
    lb = results.get("lb")
    if lb:
        L.append("## E2 Load balancing (30 curls per algorithm)")
        L.append("")
        L.append("| Algo | Spread (srv1/srv2/srv3) | Answered | Mean | p99 |")
        L.append("|---|---|---|---|---|")
        for a in ("round_robin", "least_conn", "weighted"):
            if a not in lb:
                continue
            r = lb[a]
            spread = "/".join(str(r.get("hits", {}).get(b, 0)) for b in cfg.BACKENDS)
            L.append(f"| {a} | {spread} | {r.get('answered')} | {r.get('mean_ms')} ms | "
                     f"{r.get('p99_ms')} ms |")
        L.append("")
        L.append("![lb](lb.png)")
        L.append("")
    fo = results.get("failover")
    if fo:
        L.append("## E3 Failover (s1-s2 cut during 20 Hz VIP ping)")
        L.append("")
        L.append("| Scheme | Median outage | Trials (ms) |")
        L.append("|---|---|---|")
        for key, name in (("sdn", "SDN restoration"), ("rstp", "RSTP"), ("stp", "STP")):
            sec = fo.get(key)
            if not sec or "trials" not in sec:
                continue
            ts = [t.get("outage_ms") for t in sec["trials"] if t.get("outage_ms") is not None]
            med = _med(ts)
            extra = ""
            if key == "sdn" and sec.get("reprogram_ms"):
                extra = f" Controller reprogram: {round(_med(sec['reprogram_ms']) or 0, 2)} ms."
            if key in ("rstp", "stp") and sec.get("initial_convergence_s") is not None:
                extra = f" Initial convergence: {sec['initial_convergence_s']} s."
            L.append(f"| {name} | {med} ms | {ts} |{extra}")
        L.append("")
        L.append("![failover](failover.png)")
        L.append("")
    se = results.get("security")
    if se:
        L.append("## E4 Security (UDP new-flow flood at the VIP)")
        L.append("")
        L.append("| Policing | Legit curls OK | Legit failed | Flood Packet-Ins dropped |")
        L.append("|---|---|---|---|")
        for key, name in (("policing_off", "OFF"), ("policing_on", "ON")):
            if key not in se:
                continue
            r = se[key]
            L.append(f"| {name} | {r['legit_ok']} | {r['legit_fail']} | {r['packetin_dropped']} |")
        L.append("")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    res = os.path.join(root, "results")
    with open(os.path.join(res, "results.json")) as fh:
        render(json.load(fh), res)
