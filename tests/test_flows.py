from src.flows import FlowTable, build_flows
from src.pcap_reader import packet_to_info
from tests.helpers import build_client_hello, tcp_flow, udp_packets


def flows_from(pkts):
    return build_flows(packet_to_info(p) for p in pkts)


def test_single_packet_hello():
    hello = build_client_hello("www.wikipedia.org")
    flows, totals = flows_from(tcp_flow("10.0.0.2", 50000, "93.184.0.1", 443, hello))
    assert len(flows) == 1
    f = flows[0]
    assert f.sni == "www.wikipedia.org" and f.hello_status == "ok"
    assert f.client == ("10.0.0.2", 50000) and f.server == ("93.184.0.1", 443)
    assert totals["tcp"] == totals["packets"] == 5


def test_hello_split_over_two_segments():
    hello = build_client_hello("split.example.net", pad_to=1900)
    flows, _ = flows_from(tcp_flow("10.0.0.2", 50001, "1.2.3.4", 443, hello,
                                   split=1400))
    assert flows[0].sni == "split.example.net"


def test_retransmitted_segment_is_ignored():
    hello = build_client_hello("retx.example.net", pad_to=1900)
    flows, _ = flows_from(tcp_flow("10.0.0.2", 50002, "1.2.3.4", 443, hello,
                                   split=1400, retransmit=True))
    assert flows[0].sni == "retx.example.net"


def test_missing_second_segment_is_incomplete():
    hello = build_client_hello("gap.example.net", pad_to=1900)
    pkts = tcp_flow("10.0.0.2", 50003, "1.2.3.4", 443, hello, split=1400)
    pkts = [p for i, p in enumerate(pkts) if i != 4]    # drop second part
    flows, _ = flows_from(pkts)
    assert flows[0].sni is None and flows[0].hello_status == "incomplete"


def test_hello_without_sni():
    flows, _ = flows_from(tcp_flow("10.0.0.2", 50004, "1.2.3.4", 443,
                                   build_client_hello(None)))
    assert flows[0].hello_status == "no_sni"


def test_non_tls_tcp_flow():
    flows, _ = flows_from(tcp_flow("10.0.0.2", 50005, "1.2.3.4", 80,
                                   b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert flows[0].hello_status == "not_tls" and flows[0].sni is None


def test_udp_flow_not_inspected():
    flows, _ = flows_from(udp_packets("10.0.0.2", 40000, "8.8.8.8", 53))
    assert flows[0].proto == "udp" and flows[0].hello_status == "not_applicable"


def test_two_flows_are_kept_apart_and_records_limited():
    pkts = (tcp_flow("10.0.0.2", 50010, "1.1.1.1", 443, build_client_hello("a.com"))
            + tcp_flow("10.0.0.2", 50011, "2.2.2.2", 443, build_client_hello("b.com"),
                       t0=2000.0))
    flows, _ = flows_from(pkts)
    assert sorted(f.sni for f in flows) == ["a.com", "b.com"]
    f = flows[0]
    assert all(r.payload > 0 for r in f.records)
    assert [r.direction for r in f.records] == [1, -1]
