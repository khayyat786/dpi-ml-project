"""Helpers that build fake TLS ClientHellos and fake packet captures."""
import struct
from pathlib import Path
from typing import List, Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


def build_client_hello(sni: Optional[str], pad_to: int = 0) -> bytes:
    """Build the bytes of a TLS ClientHello record (optionally padded)."""
    session_id = b"\x22" * 32
    ciphers = b"\x13\x01\x13\x02\xc0\x2b\xc0\x2f"
    exts = b""
    if sni is not None:
        name = sni.encode()
        sni_ext = (struct.pack("!H", len(name) + 3) + b"\x00"
                   + struct.pack("!H", len(name)) + name)
        exts += struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    exts += struct.pack("!HH", 10, 4) + struct.pack("!HH", 2, 0x001D)
    body = (b"\x03\x03" + b"\x11" * 32 + bytes([len(session_id)]) + session_id
            + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00")
    total = 5 + 4 + len(body) + 2 + len(exts)
    if pad_to > total + 4:
        pad = pad_to - total - 4
        exts += struct.pack("!HH", 21, pad) + b"\x00" * pad
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tcp_flow(client_ip, cport, server_ip, sport, hello: bytes, split: int = 0,
             t0: float = 1000.0, server_bytes: int = 3000, retransmit=False):
    """Packets of one HTTPS connection. `split` cuts the hello into 2 segments."""
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
    c = eth / IP(src=client_ip, dst=server_ip)
    s = (Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
         / IP(src=server_ip, dst=client_ip))
    cseq, sseq = 5000, 9000
    pkts = [
        c / TCP(sport=cport, dport=sport, flags="S", seq=cseq - 1),
        s / TCP(sport=sport, dport=cport, flags="SA", seq=sseq - 1, ack=cseq),
        c / TCP(sport=cport, dport=sport, flags="A", seq=cseq, ack=sseq),
    ]
    parts = [hello] if not split else [hello[:split], hello[split:]]
    seq = cseq
    for part in parts:
        pkts.append(c / TCP(sport=cport, dport=sport, flags="PA", seq=seq,
                            ack=sseq) / Raw(load=part))
        if retransmit and part is parts[0]:
            pkts.append(c / TCP(sport=cport, dport=sport, flags="PA", seq=seq,
                                ack=sseq) / Raw(load=part))
        seq += len(part)
    pkts.append(s / TCP(sport=sport, dport=cport, flags="PA", seq=sseq,
                        ack=seq) / Raw(load=b"\x17" * server_bytes))
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


def udp_packets(client_ip, cport, server_ip, sport, t0=1000.0, n=3):
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
    pkts = [eth / IP(src=client_ip, dst=server_ip)
            / UDP(sport=cport, dport=sport) / Raw(load=b"x" * 40)
            for _ in range(n)]
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


def write_capture(path: Path, packets: List) -> Path:
    wrpcap(str(path), packets)
    return path


def tcp_flow_data(client_ip, cport, server_ip, sport, sni, server_sizes,
                  client_sizes, gap=0.01, t0=1000.0):
    """One HTTPS flow with a ClientHello and then alternating data packets."""
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
    c = eth / IP(src=client_ip, dst=server_ip)
    s = (Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
         / IP(src=server_ip, dst=client_ip))
    hello = build_client_hello(sni)
    cseq, sseq = 5000, 9000
    pkts = [c / TCP(sport=cport, dport=sport, flags="S", seq=cseq - 1),
            s / TCP(sport=sport, dport=cport, flags="SA", seq=sseq - 1,
                    ack=cseq),
            c / TCP(sport=cport, dport=sport, flags="A", seq=cseq, ack=sseq),
            c / TCP(sport=cport, dport=sport, flags="PA", seq=cseq,
                    ack=sseq) / Raw(load=hello)]
    cseq += len(hello)
    for i in range(max(len(server_sizes), len(client_sizes))):
        if i < len(server_sizes):
            pkts.append(s / TCP(sport=sport, dport=cport, flags="PA",
                                seq=sseq, ack=cseq)
                        / Raw(load=b"\x17" * server_sizes[i]))
            sseq += server_sizes[i]
        if i < len(client_sizes):
            pkts.append(c / TCP(sport=cport, dport=sport, flags="PA",
                                seq=cseq, ack=sseq)
                        / Raw(load=b"\x17" * client_sizes[i]))
            cseq += client_sizes[i]
    for i, p in enumerate(pkts):
        p.time = t0 + i * gap
    return pkts
