"""Shared UDP framing and network utilities for VPNProxy.

Consolidated from duplicate implementations in server.py and client.py
to ensure a single source of truth for the wire protocol.

Wire format for framed UDP over TLS:
    ver(1) + rsv(1) + host_len(2 big-endian) + host(UTF-8) +
    port(2 big-endian) + payload_len(2 big-endian) + payload
"""

import asyncio
import struct

UDP_FRAME_VERSION = 1


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly n bytes from the stream, or raise IncompleteReadError."""
    return await reader.readexactly(n)


def pack_udp_frame(host: str, port: int, data: bytes) -> bytes:
    """Pack a (host, port, data) triple into the framed UDP wire format.

    Raises ValueError if host or payload exceed protocol limits.
    """
    hb = host.encode("utf-8")
    if len(hb) > 1024:
        raise ValueError("host too long")
    if len(data) > 65535:
        raise ValueError("datagram too large")
    return (
        bytes([UDP_FRAME_VERSION, 0])
        + len(hb).to_bytes(2, "big")
        + hb
        + struct.pack("!HH", port, len(data))
        + data
    )


async def read_udp_frame(reader: asyncio.StreamReader) -> tuple[str, int, bytes, int]:
    """Read and parse one framed UDP packet from the TLS stream.

    Returns (host, port, payload, wire_length) where wire_length is the
    total number of bytes consumed from the stream (header + payload).
    """
    ver_rsv_nlen = await read_exact(reader, 4)
    ver, _rsv, nlen = ver_rsv_nlen[0], ver_rsv_nlen[1], int.from_bytes(ver_rsv_nlen[2:4], "big")
    if ver != UDP_FRAME_VERSION:
        raise ValueError("bad udp frame version")
    if nlen == 0 or nlen > 1024:
        raise ValueError("bad udp frame host length")
    host_b = await read_exact(reader, nlen)
    host = host_b.decode("utf-8", errors="replace")
    port_dlen = await read_exact(reader, 4)
    port, dlen = struct.unpack("!HH", port_dlen)
    if dlen > 65535:
        raise ValueError("bad udp frame payload length")
    data = await read_exact(reader, dlen) if dlen else b""
    wire_len = 4 + nlen + 4 + len(data)
    return host, port, data, wire_len
