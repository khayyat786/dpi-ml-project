"""E1: check that our SNI parser finds the same website names as Wireshark.

Wireshark's command-line tool (tshark) is installed together with Wireshark.
For every capture file we compare, per ClientHello, the name tshark reads with
the name our parser reads. Result: results/e1_comparison.csv

Usage (from the project folder):
    python -m experiments.e1_compare_tshark data/networkB_uniwifi
"""
import argparse
import csv
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from src.baseline_dpi import find_captures
from src.flows import build_flows
from src.pcap_reader import read_packets

WINDOWS_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def find_tshark() -> Optional[str]:
    path = shutil.which("tshark")
    if path:
        return path
    if Path(WINDOWS_TSHARK).exists():
        return WINDOWS_TSHARK
    return None


def tshark_names(tshark: str, pcap: Path) -> Dict[Tuple[str, int, str, int], str]:
    """Map (client_ip, client_port, server_ip, server_port) -> SNI per tshark."""
    cmd = [tshark, "-r", str(pcap), "-Y", "tls.handshake.type == 1",
           "-T", "fields", "-E", "separator=/t",
           "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport",
           "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport",
           "-e", "tls.handshake.extensions_server_name"]
    res = subprocess.run(cmd, capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    names: Dict[Tuple[str, int, str, int], str] = {}
    for line in res.stdout.splitlines():
        cols = line.split("\t") + [""] * 7
        src = cols[0] or cols[1]
        dst = cols[3] or cols[4]
        if not (src and dst and cols[2] and cols[5]):
            continue                      # not a TCP ClientHello
        sni = cols[6].split(",")[0].strip().lower()
        names[(src, int(cols[2]), dst, int(cols[5]))] = sni
    return names


def our_names(pcap: Path) -> Dict[Tuple[str, int, str, int], str]:
    flows, _ = build_flows(read_packets(pcap))
    return {(f.client[0], f.client[1], f.server[0], f.server[1]): f.sni
            for f in flows if f.sni}


def compare(ours: dict, theirs: dict) -> Tuple[dict, list]:
    wire_with_name = {k: v for k, v in theirs.items() if v}
    equal = [k for k, v in wire_with_name.items() if ours.get(k) == v]
    different = [k for k, v in wire_with_name.items()
                 if k in ours and ours[k] != v]
    missed = [k for k in wire_with_name if k not in ours]
    extra = [k for k in ours if k not in wire_with_name]
    stats = {
        "tshark_hellos_with_name": len(wire_with_name),
        "ours_found": len(ours),
        "same": len(equal), "different": len(different),
        "missed_by_us": len(missed), "only_ours": len(extra),
        "agreement_pct": round(100 * len(equal) / len(wire_with_name), 2)
        if wire_with_name else 100.0,
    }
    issues = ([("different", k, wire_with_name[k], ours[k]) for k in different]
              + [("missed_by_us", k, wire_with_name[k], "") for k in missed]
              + [("only_ours", k, "", ours[k]) for k in extra])
    return stats, issues


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", default="results")
    args = ap.parse_args(argv)

    tshark = find_tshark()
    if not tshark:
        print("tshark was not found. It comes with Wireshark, normally at\n"
              f"  {WINDOWS_TSHARK}\nInstall or repair Wireshark and try again.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    all_stats, all_issues = [], []
    for pcap in find_captures(args.paths):
        stats, issues = compare(our_names(pcap), tshark_names(tshark, pcap))
        stats = {"file": pcap.name, **stats}
        all_stats.append(stats)
        all_issues += [(pcap.name,) + i for i in issues]
        print(f"{pcap.name}: tshark {stats['tshark_hellos_with_name']}, "
              f"same {stats['same']}, different {stats['different']}, "
              f"missed {stats['missed_by_us']}, only ours {stats['only_ours']}"
              f"  -> agreement {stats['agreement_pct']}%")
    if not all_stats:
        print("No capture files found.")
        return 1
    with open(out / "e1_comparison.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_stats[0]))
        w.writeheader()
        w.writerows(all_stats)
    with open(out / "e1_mismatches.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "kind", "flow", "tshark_name", "our_name"])
        w.writerows(all_issues)
    tot = sum(s["tshark_hellos_with_name"] for s in all_stats)
    same = sum(s["same"] for s in all_stats)
    print(f"\nOverall: {same} of {tot} ClientHello names agree "
          f"({100 * same / tot:.2f}%)" if tot else "\nNo names found.")
    print(f"Saved {out / 'e1_comparison.csv'} and {out / 'e1_mismatches.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
