"""Behavior features from the first packets of a flow (no website name needed).

The decision is made after N packets. Features use only those N packets, so
nothing from the future leaks in. The client's opening packets (the
ClientHello, whose size depends on the length of the website name) are
skipped: the window starts at the first packet the server sends.
"""
from typing import Dict, List, Optional

import numpy as np

from .flows import PacketRecord

FEATURE_NAMES = [
    "n_pkts", "n_c2s", "n_s2c", "bytes_c2s", "bytes_s2c", "frac_bytes_c2s",
    "size_mean", "size_std", "size_min", "size_max",
    "c2s_size_mean", "s2c_size_mean", "first_s2c_size",
    "iat_mean", "iat_std", "iat_max", "window_duration",
]


def feature_window(records: List[PacketRecord], n: int) -> List[PacketRecord]:
    """The first n payload packets, starting at the server's first packet."""
    i = 0
    while i < len(records) and records[i].direction == 1:
        i += 1
    return records[i:i + n]


def flow_features(records: List[PacketRecord], n: int) -> Optional[Dict[str, float]]:
    """Return the feature dict for the first n packets, or None if no window."""
    w = feature_window(records, n)
    if not w:
        return None
    sizes = np.array([r.payload for r in w], dtype=float)
    dirs = np.array([r.direction for r in w])
    ts = np.array([r.ts for r in w], dtype=float)
    iat = np.diff(ts) if len(ts) > 1 else np.zeros(1)
    c2s = sizes[dirs == 1]
    s2c = sizes[dirs == -1]
    total = float(sizes.sum())
    return {
        "n_pkts": float(len(w)),
        "n_c2s": float(len(c2s)),
        "n_s2c": float(len(s2c)),
        "bytes_c2s": float(c2s.sum()),
        "bytes_s2c": float(s2c.sum()),
        "frac_bytes_c2s": float(c2s.sum() / total) if total else 0.0,
        "size_mean": float(sizes.mean()),
        "size_std": float(sizes.std()),
        "size_min": float(sizes.min()),
        "size_max": float(sizes.max()),
        "c2s_size_mean": float(c2s.mean()) if len(c2s) else 0.0,
        "s2c_size_mean": float(s2c.mean()) if len(s2c) else 0.0,
        "first_s2c_size": float(s2c[0]) if len(s2c) else 0.0,
        "iat_mean": float(iat.mean()),
        "iat_std": float(iat.std()),
        "iat_max": float(iat.max()),
        "window_duration": float(ts[-1] - ts[0]),
    }
