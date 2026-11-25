from src.sni_parser import (INCOMPLETE, MALFORMED, NO_SNI, NOT_TLS, OK,
                            parse_client_hello)
from tests.helpers import build_client_hello


def test_reads_sni():
    r = parse_client_hello(build_client_hello("www.Example.com"))
    assert r.status == OK and r.sni == "www.example.com"


def test_hello_without_sni():
    r = parse_client_hello(build_client_hello(None))
    assert r.status == NO_SNI and r.sni is None


def test_large_padded_hello():
    data = build_client_hello("big.example.org", pad_to=1900)
    assert len(data) >= 1900
    assert parse_client_hello(data).sni == "big.example.org"


def test_truncated_is_incomplete():
    data = build_client_hello("example.com")
    assert parse_client_hello(data[:40]).status == INCOMPLETE
    assert parse_client_hello(b"").status == INCOMPLETE


def test_non_tls():
    assert parse_client_hello(b"GET / HTTP/1.1\r\n").status == NOT_TLS
    assert parse_client_hello(b"\x17\x03\x03\x00\x10" + b"\x00" * 16).status == NOT_TLS


def test_server_hello_is_not_a_client_hello():
    data = bytearray(build_client_hello("example.com"))
    data[5] = 0x02                       # handshake type ServerHello
    assert parse_client_hello(bytes(data)).status == NOT_TLS


def test_garbage_inside_record_is_malformed():
    data = bytearray(build_client_hello("example.com"))
    data[43] = 0xFF                      # absurd session-id length
    assert parse_client_hello(bytes(data)).status == MALFORMED
