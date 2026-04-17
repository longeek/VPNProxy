#!/usr/bin/env python3
"""Smoke tests for local VPNProxy client: TCP line protocol and SOCKS5 UDP ASSOCIATE."""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys


def tcp_line_http_get(host: str, port: int, line_host: str, line_port: int) -> None:
    payload = f"{host}:{port}\n".encode()
    with socket.create_connection((line_host, line_port), timeout=20) as s:
        s.sendall(payload)
        buf = s.recv(128)
        if not buf.startswith(b"OK"):
            raise SystemExit(f"TCP line: expected OK, got {buf!r}")
        req = (
            f"GET /ip HTTP/1.0\r\nHost: {host}\r\n"
            "User-Agent: vpnproxy-smoke\r\n\r\n"
        ).encode()
        s.sendall(req)
        resp = s.recv(65536)
    if b"200" not in resp and b"origin" not in resp:
        raise SystemExit(f"TCP line: bad HTTP response head {resp[:120]!r}")
    print("[PASS] TCP line -> http GET /ip")


def _readn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("SOCKS5: connection closed")
        buf += chunk
    return buf


def _recv_socks5_connect_reply(sock: socket.socket) -> tuple[str, int]:
    head = _readn(sock, 4)
    ver, rep, _rsv, atyp = head[0], head[1], head[2], head[3]
    if ver != 5 or rep != 0:
        raise SystemExit(f"SOCKS5: ver={ver} rep={rep}")
    if atyp == 1:
        rest = _readn(sock, 6)
        ip = socket.inet_ntoa(rest[:4])
        port = struct.unpack("!H", rest[4:6])[0]
        return ip, port
    if atyp == 3:
        ln = _readn(sock, 1)[0]
        host = _readn(sock, ln).decode("utf-8", errors="replace")
        port = struct.unpack("!H", _readn(sock, 2))[0]
        return host, port
    if atyp == 4:
        rest = _readn(sock, 18)
        ip = socket.inet_ntop(socket.AF_INET6, rest[:16])
        port = struct.unpack("!H", rest[16:18])[0]
        return ip, port
    raise SystemExit(f"SOCKS5: bad atyp {atyp}")


def _socks_udp_packet(dest_host: str, dest_port: int, inner: bytes) -> bytes:
    try:
        packed = socket.inet_aton(dest_host)
        head = b"\x00\x00\x00\x01" + packed + struct.pack("!H", dest_port)
    except OSError:
        b = dest_host.encode("utf-8")
        head = b"\x00\x00\x00\x03" + bytes([len(b)]) + b + struct.pack("!H", dest_port)
    return head + inner


def _parse_socks_udp_response(data: bytes) -> bytes:
    if len(data) < 10 or data[0:3] != b"\x00\x00\x00":
        raise SystemExit(f"SOCKS UDP: bad header {data[:16]!r}")
    atyp = data[3]
    off = 4
    if atyp == 1:
        off += 4 + 2
    elif atyp == 3:
        ln = data[off]
        off += 1 + ln + 2
    elif atyp == 4:
        off += 16 + 2
    else:
        raise SystemExit(f"SOCKS UDP: atyp {atyp}")
    return data[off:]


def _dns_query_a(name: str) -> bytes:
    tid = random.randint(1, 65535)
    hdr = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    q = qname + struct.pack("!HH", 1, 1)
    return hdr + q


def socks5_udp_dns(socks_host: str, socks_port: int, dns_server: str, qname: str) -> None:
    tcp = socket.create_connection((socks_host, socks_port), timeout=15)
    try:
        tcp.sendall(b"\x05\x01\x00")
        if tcp.recv(2) != b"\x05\x00":
            raise SystemExit("SOCKS5: auth method")
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        bnd_host, bnd_port = _recv_socks5_connect_reply(tcp)
    except Exception:
        tcp.close()
        raise

    query = _dns_query_a(qname)
    pkt = _socks_udp_packet(dns_server, 53, query)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.settimeout(15)
        udp.sendto(pkt, (bnd_host, bnd_port))
        data, _ = udp.recvfrom(4096)
    finally:
        udp.close()
        tcp.close()

    dns_payload = _parse_socks_udp_response(data)
    if len(dns_payload) < 12:
        raise SystemExit("SOCKS UDP: short DNS payload")
    print("[PASS] SOCKS5 UDP ASSOCIATE -> DNS", qname, "via", dns_server)


def main() -> None:
    p = argparse.ArgumentParser(description="VPNProxy TCP line + SOCKS5 UDP smoke tests")
    p.add_argument("--tcp-line-host", default="127.0.0.1")
    p.add_argument("--tcp-line-port", type=int, default=1081)
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=1080)
    p.add_argument("--skip-tcp-line", action="store_true")
    p.add_argument("--skip-socks-udp", action="store_true")
    args = p.parse_args()

    if not args.skip_tcp_line:
        tcp_line_http_get("httpbin.org", 80, args.tcp_line_host, args.tcp_line_port)
    if not args.skip_socks_udp:
        socks5_udp_dns(args.socks_host, args.socks_port, "8.8.8.8", "example.com")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[FAIL]", e, file=sys.stderr)
        sys.exit(1)
