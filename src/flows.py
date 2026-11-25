"""Group packets into flows (conversations) and find each flow's SNI.

A flow is identified by its 5-tuple: protocol, source IP, source port,
destination IP and destination port. Both directions belong to one flow.
For TCP flows the first bytes the client sends are put back in order, so a
ClientHello that is split over several packets can still be read.
"""
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .pcap_reader import PacketInfo
from .sni_parser import (INCOMPLETE, OK, parse_client_hello)

MAX_RECORDED = 50              # payload packets remembered per flow (for features)
MAX_REASSEMBLY_BYTES = 20000   # how much of the client's stream we reassemble
MAX_HELLO_ATTEMPTS = 12        # client data packets tried before giving up


@dataclass
class PacketRecord:
    """Minimal facts about one packet, kept for the ML features later."""
    ts: float
    direction: int      # +1 = client to server, -1 = server to client
    size: int           # size on the wire (bytes)
    payload: int        # transport payload (bytes)


@dataclass
class Flow:
    proto: str
    client: Tuple[str, int]
    server: Tuple[str, int]
    first_ts: float
    last_ts: float
    packets: int = 0
    byte_count: int = 0
    sni: Optional[str] = None
    hello_status: str = "pending"
    records: List[PacketRecord] = field(default_factory=list)
    _segments: Dict[int, bytes] = field(default_factory=dict, repr=False)
    _base_seq: Optional[int] = field(default=None, repr=False)
    _attempts: int = field(default=0, repr=False)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


def _pick_client(p: PacketInfo) -> bool:
    """Return True if the packet's sender is the client of the flow."""
    if p.proto == "tcp":
        if p.syn and not p.ack:
            return True
        if p.syn and p.ack:
            return False
    if p.dst_port == 443 or (p.dst_port < 1024 <= p.src_port):
        return True
    if p.src_port == 443 or (p.src_port < 1024 <= p.dst_port):
        return False
    return True


class FlowTable:
    def __init__(self) -> None:
        self.flows: Dict[tuple, Flow] = {}

    @staticmethod
    def _key(p: PacketInfo) -> tuple:
        a = (p.src_ip, p.src_port)
        b = (p.dst_ip, p.dst_port)
        return (p.proto,) + ((a, b) if a <= b else (b, a))

    def add(self, p: PacketInfo) -> Optional[Flow]:
        if p.proto not in ("tcp", "udp"):
            return None
        key = self._key(p)
        flow = self.flows.get(key)
        src = (p.src_ip, p.src_port)
        dst = (p.dst_ip, p.dst_port)
        if flow is None:
            sender_is_client = _pick_client(p)
            client, server = (src, dst) if sender_is_client else (dst, src)
            flow = Flow(p.proto, client, server, p.ts, p.ts)
            self.flows[key] = flow
        direction = 1 if src == flow.client else -1

        flow.packets += 1
        flow.byte_count += p.wirelen
        flow.last_ts = max(flow.last_ts, p.ts)
        if p.payload_len > 0 and len(flow.records) < MAX_RECORDED:
            flow.records.append(
                PacketRecord(p.ts, direction, p.wirelen, p.payload_len))

        if (p.proto == "tcp" and direction == 1 and p.payload
                and flow.hello_status == "pending"):
            self._try_client_hello(flow, p)
        return flow

    @staticmethod
    def _try_client_hello(flow: Flow, p: PacketInfo) -> None:
        if flow._base_seq is None:
            flow._base_seq = p.seq
        rel = (p.seq - flow._base_seq) & 0xFFFFFFFF
        if rel >= (1 << 31):
            return                      # older than the first data we saw
        if rel < MAX_REASSEMBLY_BYTES and rel not in flow._segments:
            flow._segments[rel] = p.payload
        flow._attempts += 1

        data = bytearray()
        for off in sorted(flow._segments):
            seg = flow._segments[off]
            if off > len(data):
                break                   # a gap: a packet is missing
            if off + len(seg) > len(data):
                data += seg[len(data) - off:]
        result = parse_client_hello(bytes(data))
        if result.status == INCOMPLETE and flow._attempts < MAX_HELLO_ATTEMPTS:
            return
        flow.hello_status = result.status
        if result.status == OK:
            flow.sni = result.sni

    def finish(self) -> List[Flow]:
        """Close the table and return the flows in the order they started."""
        for flow in self.flows.values():
            if flow.proto != "tcp":
                flow.hello_status = "not_applicable"
            elif flow.hello_status == "pending":
                flow.hello_status = ("incomplete" if flow._segments
                                     else "no_client_data")
        return sorted(self.flows.values(), key=lambda f: f.first_ts)


def build_flows(packets: Iterable[PacketInfo]) -> Tuple[List[Flow], Dict[str, int]]:
    """Build all flows of a capture and count packets and bytes by protocol."""
    table = FlowTable()
    totals = {"packets": 0, "bytes": 0, "tcp": 0, "udp": 0, "other": 0}
    for p in packets:
        totals["packets"] += 1
        totals["bytes"] += p.wirelen
        totals[p.proto] += 1
        table.add(p)
    return table.finish(), totals
