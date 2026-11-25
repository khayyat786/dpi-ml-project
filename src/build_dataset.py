"""Build the labeled dataset: capture files -> one row per labeled flow.

Usage (from the project folder):
    python -m src.build_dataset data\networkB_uniwifi
Writes results/dataset_n5.csv, dataset_n10.csv, dataset_n20.csv (features
from the first 5 / 10 / 20 packets), results/labeling_summary.csv and
results/shared_websites.csv.
"""
import argparse
import csv
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Sequence

import pandas as pd

from .baseline_dpi import find_captures
from .features import FEATURE_NAMES, flow_features
from .flows import build_flows
from .labeling import (load_label_config, parse_capture_name, select_labeled,
                       site_key)
from .pcap_reader import read_packets

DEFAULT_NS = (5, 10, 20)


def build(paths: Iterable[str], labels_cfg: str = "config/labels.yaml",
          out_dir: str = "results", ns: Sequence[int] = DEFAULT_NS) -> dict:
    cfg = load_label_config(labels_cfg)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    items: List[dict] = []
    stats: Counter = Counter()
    for path in find_captures(paths):
        info = parse_capture_name(path)
        cls = cfg["prefix_to_class"].get(info["prefix"])
        if cls is None or cls not in cfg["classes"]:
            print(f"skipping {path.name}: class '{cls}' is not in use")
            continue
        flows, _ = build_flows(read_packets(path))
        stats["files"] += 1
        for f in flows:
            if f.proto != "tcp":
                stats["udp_flows"] += 1
            elif not f.sni:
                stats["tcp_flows_without_sni"] += 1
            else:
                items.append({"file": path.name, "network": info["network"],
                              "session": info["session"], "label_class": cls,
                              "sni": f.sni, "flow": f})
    stats["tcp_flows_with_sni"] = len(items)

    kept, reasons, shared = select_labeled(items, cfg)

    # drop classes with too few flows
    per_class = Counter(it["label_class"] for it in kept)
    too_small = {c for c, n in per_class.items()
                 if n < cfg["min_flows_per_class"]}
    for c in too_small:
        print(f"warning: class '{c}' has only {per_class[c]} labeled flows "
              f"and is dropped (minimum {cfg['min_flows_per_class']})")
    kept = [it for it in kept if it["label_class"] not in too_small]

    written = {}
    for n in ns:
        rows = []
        for it in kept:
            feats = flow_features(it["flow"].records, n)
            if feats is None:
                stats[f"n{n}_no_packets_after_hello"] += 1
                continue
            rows.append({"file": it["file"], "network": it["network"],
                         "session": it["session"], "label": it["label_class"],
                         "sni": it["sni"], "site": site_key(it["sni"]),
                         **{k: feats[k] for k in FEATURE_NAMES}})
        df = pd.DataFrame(rows)
        df.to_csv(out / f"dataset_n{n}.csv", index=False)
        written[n] = df

    with open(out / "labeling_summary.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item", "count"])
        for k, v in sorted(stats.items()):
            w.writerow([k, v])
        for k, v in sorted(reasons.items()):
            w.writerow([f"label_{k}", v])
        for c, v in sorted(per_class.items()):
            w.writerow([f"class_{c}_labeled_flows", v])
    with open(out / "shared_websites.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["website", "seen_in_classes"])
        for s, c in sorted(shared.items()):
            w.writerow([s, " ".join(sorted(c))])

    print("\nLabeling summary")
    print(f"  capture files used: {stats['files']}")
    print(f"  TCP flows with a visible website name: {stats['tcp_flows_with_sni']}")
    print(f"  ignored as background traffic: {reasons['ignored_background']}")
    print(f"  dropped (website appears in several classes): "
          f"{reasons['shared_between_classes']}")
    print(f"  labeled flows kept: {len(kept)}")
    for c, n in sorted(per_class.items()):
        mark = "  (dropped)" if c in too_small else ""
        print(f"    {c}: {n}{mark}")
    for n, df in written.items():
        print(f"  dataset_n{n}.csv: {len(df)} rows")
    return {"stats": stats, "reasons": reasons, "per_class": per_class,
            "shared": shared, "datasets": written}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the labeled dataset")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--labels", default="config/labels.yaml")
    ap.add_argument("--out", default="results")
    args = ap.parse_args(argv)
    build(args.paths, args.labels, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
