"""Self-labeling: give each flow with a visible SNI a class label.

Rules (all explained in the report):
  1. Only flows whose website name (SNI) was read can be labeled.
  2. Background traffic (operating system, antivirus, browser) is ignored.
  3. A website that shows up in more than one class (for example a shared
     font or script server) says nothing about the class, so it is dropped.
  4. The label is the activity of the capture session, taken from the file
     name (youtube_B_01 -> youtube).
"""
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple, Union

import yaml

# second-level labels such as co.uk, edu.pk, com.pk
TWO_PART_SECOND_LEVEL = {"co", "com", "edu", "org", "net", "gov", "ac"}


def site_key(host: str) -> str:
    """Reduce a host name to its site, e.g. rr2.googlevideo.com -> googlevideo.com."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in TWO_PART_SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_label_config(path: Union[str, Path]) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("classes", [])
    cfg.setdefault("prefix_to_class", {})
    cfg.setdefault("ignore_domains", [])
    cfg.setdefault("min_flows_per_class", 30)
    return cfg


def parse_capture_name(path: Union[str, Path]) -> Dict[str, object]:
    """youtube_B_01.pcapng -> prefix 'youtube', network 'B', session 1."""
    parts = Path(path).stem.lower().split("_")
    prefix = parts[0]
    network = parts[1].upper() if len(parts) > 1 else "?"
    session = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return {"prefix": prefix, "network": network, "session": session}


def is_ignored(host: str, ignore_domains: List[str]) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in ignore_domains)


def select_labeled(items: List[dict], cfg: dict
                   ) -> Tuple[List[dict], Counter, Dict[str, Set[str]]]:
    """Apply the labeling rules.

    `items` are dicts with keys: label_class (activity class), sni.
    Returns (kept items, reasons Counter, shared sites {site: classes}).
    """
    reasons: Counter = Counter()
    ignore = cfg["ignore_domains"]

    candidates = []
    for it in items:
        if is_ignored(it["sni"], ignore):
            reasons["ignored_background"] += 1
            continue
        candidates.append(it)

    classes_per_site: Dict[str, Set[str]] = defaultdict(set)
    for it in candidates:
        classes_per_site[site_key(it["sni"])].add(it["label_class"])
    shared = {s: c for s, c in classes_per_site.items() if len(c) > 1}

    kept = []
    for it in candidates:
        if site_key(it["sni"]) in shared:
            reasons["shared_between_classes"] += 1
            continue
        kept.append(it)
    reasons["kept"] = len(kept)
    return kept, reasons, shared
