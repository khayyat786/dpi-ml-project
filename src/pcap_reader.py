"""Read packets from .pcap / .pcapng files and turn them into simple records."""
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Union

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


@dataclass
class PacketInfo:
    ts: float                 # capture time in seconds
    wirelen: int              # size of the packet on the wire, in bytes
    proto: str                # "tcp", "udp" or "other"
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    seq: int = 0              # TCP sequence number
    flags: int = 0            # TCP flags
    payload: bytes = b""      # TCP payload bytes (empty for UDP and others)
    payload_len: int = 0      # transport payload size in bytes

    @property
    def syn(self) -> bool:
        return bool(self.flags & TCP_SYN)

    @property
    def ack(self) -> bool:
        return bool(self.flags & TCP_ACK)


def packet_to_info(pkt) -> PacketInfo:
    """Convert one scapy packet to a PacketInfo."""
    ts = float(pkt.time)
    wirelen = int(getattr(pkt, "wirelen", 0) or len(pkt))
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return PacketInfo(ts, wirelen, "other")

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        return PacketInfo(ts, wirelen, "tcp", src, int(t.sport), dst,
                          int(t.dport), int(t.seq), int(t.flags), payload,
                          len(payload))
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        plen = max(int(u.len or 0) - 8, 0)
        return PacketInfo(ts, wirelen, "udp", src, int(u.sport), dst,
                          int(u.dport), payload_len=plen)
    return PacketInfo(ts, wirelen, "other", src, 0, dst, 0)


def read_packets(path: Union[str, Path]) -> Iterator[PacketInfo]:
    """Yield every packet of a capture file, one at a time."""
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield packet_to_info(pkt)
