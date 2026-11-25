"""Baseline DPI: the existing approach.

Reads capture files, groups packets into flows, reads the SNI (website name)
of each TLS flow, applies the rules in config/rules.yaml and prints a report.
BLOCK and THROTTLE are simulated: flows are counted, not really dropped.

Usage (from the project folder):
    python -m src.baseline_dpi data/networkB_uniwifi
    python -m src.baseline_dpi data/networkB_uniwifi/youtube_B_01.pcapng
"""
import argparse
import csv
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .flows import Flow, build_flows
from .pcap_reader import read_packets
from .rules import ALLOW, BLOCK, THROTTLE, RuleEngine

SKIP_PREFIXES = ("test_", "failed_")   # files we never use as data
CAPTURE_SUFFIXES = (".pcap", ".pcapng")

FLOW_COLUMNS = ["file", "proto", "client_ip", "client_port", "server_ip",
                "server_port", "sni", "hello_status", "action", "reason",
                "rule", "packets", "bytes", "first_ts", "duration"]


def find_captures(paths: Iterable[str], include_all: bool = False) -> List[Path]:
    """Return the capture files found in the given files and folders."""
    found: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            candidates = sorted(x for x in p.rglob("*")
                                if x.suffix.lower() in CAPTURE_SUFFIXES)
        elif p.is_file():
            candidates = [p]
        else:
            print(f"warning: {p} not found", file=sys.stderr)
            continue
        for c in candidates:
            if not include_all and c.name.lower().startswith(SKIP_PREFIXES):
                print(f"skipping {c.name} (test or failed capture)")
                continue
            found.append(c)
    return found


def classify_flow(flow: Flow, engine: RuleEngine) -> Tuple[str, str, str]:
    """Return (action, reason, matched_rule) for one flow."""
    if flow.proto != "tcp":
        return engine.default_action, "udp_not_inspected", ""
    if flow.hello_status == "ok":
        action, rule = engine.match(flow.sni)
        return action, ("rule" if rule else "default"), rule
    return engine.default_action, flow.hello_status, ""


def inspect_file(path: Path, engine: RuleEngine) -> Tuple[List[dict], dict]:
    """Run the baseline on one file. Returns (flow rows, summary)."""
    flows, totals = build_flows(read_packets(path))
    rows: List[dict] = []
    actions = Counter()          # flows per action
    action_packets = Counter()   # packets per action
    status = Counter()
    bytes_by_sni: Counter = Counter()

    for f in flows:
        action, reason, rule = classify_flow(f, engine)
        actions[action] += 1
        action_packets[action] += f.packets
        if f.proto == "tcp":
            status[f.hello_status] += 1
        if f.sni:
            bytes_by_sni[f.sni] += f.byte_count
        rows.append({
            "file": path.name, "proto": f.proto,
            "client_ip": f.client[0], "client_port": f.client[1],
            "server_ip": f.server[0], "server_port": f.server[1],
            "sni": f.sni or "", "hello_status": f.hello_status,
            "action": action, "reason": reason, "rule": rule,
            "packets": f.packets, "bytes": f.byte_count,
            "first_ts": round(f.first_ts, 6), "duration": round(f.duration, 3),
        })

    tcp_flows = sum(1 for f in flows if f.proto == "tcp")
    summary = {
        "file": path.name,
        "packets": totals["packets"], "bytes": totals["bytes"],
        "tcp_packets": totals["tcp"], "udp_packets": totals["udp"],
        "other_packets": totals["other"],
        "flows": len(flows), "tcp_flows": tcp_flows,
        "udp_flows": len(flows) - tcp_flows,
        "flows_with_sni": status["ok"],
        "flows_without_sni": tcp_flows - status["ok"],
        "block_flows": actions[BLOCK], "throttle_flows": actions[THROTTLE],
        "allow_flows": actions[ALLOW],
        "packets_dropped": action_packets[BLOCK],
        "packets_forwarded": totals["packets"] - action_packets[BLOCK],
        "status_counts": dict(status),
        "top_sni": bytes_by_sni.most_common(8),
    }
    return rows, summary


def print_report(s: dict) -> None:
    mb = s["bytes"] / 1e6
    print("=" * 62)
    print(f"File: {s['file']}")
    print("-" * 62)
    print(f"Packets: {s['packets']}  ({mb:.1f} MB)   TCP {s['tcp_packets']}"
          f"  UDP {s['udp_packets']}  other {s['other_packets']}")
    print(f"Flows: {s['flows']}  (TCP {s['tcp_flows']}, UDP {s['udp_flows']})")
    print(f"TCP flows with a website name (SNI): {s['flows_with_sni']}")
    print(f"TCP flows without one: {s['flows_without_sni']}   "
          f"{s['status_counts']}")
    print(f"Actions (flows): BLOCK {s['block_flows']}  "
          f"THROTTLE {s['throttle_flows']}  ALLOW {s['allow_flows']}")
    print(f"Packets forwarded: {s['packets_forwarded']}   "
          f"dropped: {s['packets_dropped']}")
    if s["top_sni"]:
        print("Top website names by bytes:")
        for name, nbytes in s["top_sni"]:
            print(f"   {nbytes / 1e6:8.2f} MB  {name}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Baseline SNI-based DPI")
    ap.add_argument("paths", nargs="+", help="capture files or folders")
    ap.add_argument("--rules", default="config/rules.yaml")
    ap.add_argument("--out", default="results", help="folder for the CSV files")
    ap.add_argument("--include-test", action="store_true",
                    help="also read files named test_* or failed_*")
    args = ap.parse_args(argv)

    engine = RuleEngine.from_yaml(args.rules)
    files = find_captures(args.paths, include_all=args.include_test)
    if not files:
        print("No capture files found.")
        return 1

    out = Path(args.out)
    (out / "baseline").mkdir(parents=True, exist_ok=True)
    summaries = []
    for path in files:
        rows, summary = inspect_file(path, engine)
        print_report(summary)
        with open(out / "baseline" / f"{path.stem}_flows.csv", "w",
                  newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FLOW_COLUMNS)
            w.writeheader()
            w.writerows(rows)
        summaries.append(summary)

    cols = [c for c in summaries[0] if c not in ("status_counts", "top_sni")]
    with open(out / "baseline_summary.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for s in summaries:
            w.writerow({c: s[c] for c in cols})
    print("=" * 62)
    print(f"Saved {len(summaries)} flow tables and baseline_summary.csv "
          f"in {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
