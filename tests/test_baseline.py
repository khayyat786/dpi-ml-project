import csv

import pytest

from src.baseline_dpi import find_captures, main
from tests.helpers import (build_client_hello, tcp_flow, udp_packets,
                           write_capture)


def make_packets():
    pkts = []
    pkts += tcp_flow("10.0.0.2", 50000, "142.250.0.1", 443,
                     build_client_hello("rr2---sn-abc.googlevideo.com"), t0=1000)
    pkts += tcp_flow("10.0.0.2", 50001, "142.250.0.2", 443,
                     build_client_hello("googleads.g.doubleclick.net"), t0=1001)
    pkts += tcp_flow("10.0.0.2", 50002, "208.80.0.1", 443,
                     build_client_hello("en.wikipedia.org", pad_to=1900),
                     split=1400, t0=1002)
    pkts += tcp_flow("10.0.0.2", 50003, "9.9.9.9", 443,
                     build_client_hello(None), t0=1003)
    pkts += udp_packets("10.0.0.2", 40000, "8.8.8.8", 53, t0=1004)
    return pkts


def run_and_read(tmp_path, capture):
    out = tmp_path / "res"
    assert main([str(capture), "--rules", "config/rules.yaml",
                 "--out", str(out)]) == 0
    with open(out / "baseline" / f"{capture.stem}_flows.csv") as f:
        rows = list(csv.DictReader(f))
    with open(out / "baseline_summary.csv") as f:
        summary = list(csv.DictReader(f))[0]
    return rows, summary


def test_end_to_end_pcap(tmp_path):
    cap = write_capture(tmp_path / "demo_A_01.pcap", make_packets())
    rows, s = run_and_read(tmp_path, cap)
    by_sni = {r["sni"]: r for r in rows if r["sni"]}
    assert by_sni["rr2---sn-abc.googlevideo.com"]["action"] == "THROTTLE"
    assert by_sni["googleads.g.doubleclick.net"]["action"] == "BLOCK"
    assert by_sni["en.wikipedia.org"]["action"] == "ALLOW"
    assert int(s["flows"]) == 5 and int(s["flows_with_sni"]) == 3
    assert int(s["flows_without_sni"]) == 1 and int(s["udp_flows"]) == 1
    assert int(s["block_flows"]) == 1 and int(s["throttle_flows"]) == 1
    assert int(s["packets_dropped"]) == 5
    assert int(s["packets"]) == int(s["packets_forwarded"]) + 5


def test_end_to_end_pcapng(tmp_path):
    ng = pytest.importorskip("scapy.utils").PcapNgWriter
    path = tmp_path / "demo_A_02.pcapng"
    w = ng(str(path))
    for p in make_packets():
        w.write(p)
    w.close()
    rows, s = run_and_read(tmp_path, path)
    assert int(s["flows_with_sni"]) == 3


def test_test_and_failed_files_are_skipped(tmp_path):
    for name in ("test_00_B.pcap", "failed_download_B_02.pcap", "youtube_B_01.pcap"):
        write_capture(tmp_path / name, make_packets())
    names = [p.name for p in find_captures([str(tmp_path)])]
    assert names == ["youtube_B_01.pcap"]
