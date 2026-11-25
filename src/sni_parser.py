"""Read the SNI (the website name) from a TLS ClientHello message.

The ClientHello is the first message a browser sends when it opens a secure
(HTTPS) connection. Its "server_name" extension carries the website name in
plain text. This module only reads bytes; it never decrypts anything.
"""
from dataclasses import dataclass
from typing import Optional

# Possible outcomes
OK = "ok"                  # ClientHello found and a website name was read
NO_SNI = "no_sni"          # ClientHello found but it has no website name
NOT_TLS = "not_tls"        # the data does not start like a TLS ClientHello
INCOMPLETE = "incomplete"  # looks like TLS but more bytes are needed
MALFORMED = "malformed"    # looks like TLS but the structure is broken

MAX_RECORD_LEN = 16640     # a TLS record cannot be larger than this


@dataclass
class ClientHelloResult:
    status: str
    sni: Optional[str] = None


def _u8(b: bytes, pos: int) -> int:
    if pos + 1 > len(b):
        raise ValueError("out of range")
    return b[pos]


def _u16(b: bytes, pos: int) -> int:
    if pos + 2 > len(b):
        raise ValueError("out of range")
    return int.from_bytes(b[pos:pos + 2], "big")


def _u24(b: bytes, pos: int) -> int:
    if pos + 3 > len(b):
        raise ValueError("out of range")
    return int.from_bytes(b[pos:pos + 3], "big")


def parse_client_hello(data: bytes) -> ClientHelloResult:
    """Parse the first bytes of a client's TCP stream."""
    if len(data) == 0:
        return ClientHelloResult(INCOMPLETE)
    # TLS record header: type(1) version(2) length(2). Type 0x16 = handshake.
    if data[0] != 0x16:
        return ClientHelloResult(NOT_TLS)
    if len(data) >= 2 and data[1] != 0x03:
        return ClientHelloResult(NOT_TLS)
    if len(data) < 5:
        return ClientHelloResult(INCOMPLETE)
    record_len = int.from_bytes(data[3:5], "big")
    if record_len > MAX_RECORD_LEN or record_len < 4:
        return ClientHelloResult(NOT_TLS)
    if len(data) < 5 + record_len:
        return ClientHelloResult(INCOMPLETE)
    body = data[5:5 + record_len]

    try:
        if body[0] != 0x01:                      # handshake type 1 = ClientHello
            return ClientHelloResult(NOT_TLS)
        hs_len = _u24(body, 1)
        if 4 + hs_len > len(body):               # message spans several records
            return ClientHelloResult(MALFORMED)
        hello = body[:4 + hs_len]
        pos = 4 + 2 + 32                         # header, version, random
        pos += 1 + _u8(hello, pos)               # session id
        pos += 2 + _u16(hello, pos)              # cipher suites
        pos += 1 + _u8(hello, pos)               # compression methods
        if pos == len(hello):                    # no extensions at all
            return ClientHelloResult(NO_SNI)
        ext_total = _u16(hello, pos)
        pos += 2
        ext_end = pos + ext_total
        if ext_end > len(hello):
            return ClientHelloResult(MALFORMED)
        while pos + 4 <= ext_end:
            ext_type = _u16(hello, pos)
            ext_len = _u16(hello, pos + 2)
            pos += 4
            if pos + ext_len > ext_end:
                return ClientHelloResult(MALFORMED)
            if ext_type == 0:                    # server_name extension
                p = pos + 2                      # skip the list length
                list_end = pos + ext_len
                while p + 3 <= list_end:
                    name_type = _u8(hello, p)
                    name_len = _u16(hello, p + 1)
                    p += 3
                    name = hello[p:p + name_len]
                    p += name_len
                    if name_type == 0 and name:
                        return ClientHelloResult(
                            OK, name.decode("ascii", "ignore").lower())
                return ClientHelloResult(NO_SNI)
            pos += ext_len
        return ClientHelloResult(NO_SNI)
    except ValueError:
        return ClientHelloResult(MALFORMED)
