#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import json
import logging
import os
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Optional


LOG = logging.getLogger("vpn-proxy-server")


class AuthError(Exception):
    pass


class _DnsEntry:
    __slots__ = ("ip", "expires")
    def __init__(self, ip: Optional[str], expires: float) -> None:
        self.ip = ip
        self.expires = expires


class DnsCache:
    """DNS cache with TTL and negative caching (transplanted from Go impl).

    - Positive entries cached for DNS_CACHE_TTL seconds (default 30s).
    - Negative entries (failed lookups) cached to avoid repeated retries.
    - Thread-safe via asyncio.Lock.
    """

    def __init__(self, ttl: float = 30.0) -> None:
        self._ttl = ttl
        self._cache: dict[str, _DnsEntry] = {}
        self._lock = asyncio.Lock()

    async def resolve(self, host: str) -> Optional[str]:
        """Return cached IP or resolve and cache. Returns None on failure."""
        now = time.monotonic()
        async with self._lock:
            entry = self._cache.get(host)
            if entry is not None and now < entry.expires:
                return entry.ip  # may be None (negative cache hit)

        # Cache miss: perform DNS resolution
        try:
            addrs = await asyncio.get_running_loop().getaddrinfo(host, None)
        except OSError:
            # Negative cache: remember failure for short TTL
            async with self._lock:
                self._cache[host] = _DnsEntry(None, now + self._ttl * 0.3)
            return None

        # Prefer IPv4, fallback to any
        ip: Optional[str] = None
        for family, *_rest, sockaddr in addrs:
            addr = sockaddr[0]
            if family == socket.AF_INET:
                ip = addr
                break
            if ip is None:
                ip = addr
        if ip is None:
            return None

        async with self._lock:
            self._cache[host] = _DnsEntry(ip, now + self._ttl)
        return ip


# Global DNS cache instance (shared across all connections)
_dns_cache = DnsCache()


@dataclass
class SessionStats:
    upload_bytes: int = 0
    download_bytes: int = 0


_RECV_BUF = 256 * 1024


def _set_socket_options(writer: asyncio.StreamWriter, enable_keepalive: bool = False) -> None:
    if not hasattr(writer, "get_extra_info"):
        return
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RECV_BUF)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _RECV_BUF)
    except OSError:
        pass
    if enable_keepalive:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Windows: set keepalive interval via ioctl (may not be available)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)  # type: ignore[attr-defined]
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)  # type: ignore[attr-defined]
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)  # type: ignore[attr-defined]
        except OSError:
            pass


def load_allowed_tokens(args: argparse.Namespace) -> set[str]:
    tokens: set[str] = set()
    if args.token:
        tokens.add(args.token)

    if args.tokens_file:
        with open(args.tokens_file, "r", encoding="utf-8") as f:
            for line in f:
                token = line.strip()
                if token and not token.startswith("#"):
                    tokens.add(token)
    return tokens


def parse_allow_cidrs(value: Optional[str]) -> list[ipaddress._BaseNetwork]:
    if not value:
        return []
    items = [v.strip() for v in value.split(",") if v.strip()]
    networks: list[ipaddress._BaseNetwork] = []
    for item in items:
        networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def peer_allowed(peer: object, allow_networks: list[ipaddress._BaseNetwork]) -> bool:
    if not allow_networks:
        return True
    if not isinstance(peer, tuple) or not peer:
        return False
    ip = ipaddress.ip_address(peer[0])
    return any(ip in net for net in allow_networks)


async def pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stats: SessionStats,
    is_upload: bool,
) -> None:
    drain_threshold = 128 * 1024
    pending = 0
    try:
        while True:
            data = await reader.read(131072)
            if not data:
                break
            if writer.is_closing():
                break
            if is_upload:
                stats.upload_bytes += len(data)
            else:
                stats.download_bytes += len(data)
            writer.write(data)
            pending += len(data)
            if pending >= drain_threshold:
                await writer.drain()
                pending = 0
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            if not writer.is_closing():
                writer.write_eof()
        except (ConnectionError, OSError, RuntimeError):
            pass
        try:
            writer.close()
        except (ConnectionError, OSError, RuntimeError):
            pass


def parse_bootstrap_line(line: bytes, allowed_tokens: set[str]) -> tuple[str, int, str]:
    try:
        payload = json.loads(line.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid json") from exc

    token = payload.get("auth")
    host = payload.get("host")
    port = payload.get("port")
    proto = payload.get("proto", "tcp")
    if proto not in ("tcp", "udp"):
        raise ValueError("invalid proto")

    if token not in allowed_tokens:
        raise AuthError("invalid auth token")
    if not isinstance(host, str) or not host:
        raise ValueError("invalid host")
    if not isinstance(port, int) or port < 0 or port > 65535:
        raise ValueError("invalid port")
    if proto == "tcp":
        if port < 1:
            raise ValueError("invalid port")
    else:
        # UDP relay: 0.0.0.0:0 means framed per-datagram destinations.
        if host == "0.0.0.0" and port == 0:
            pass
        elif port < 1:
            raise ValueError("invalid port")

    return host, port, proto


UDP_FRAME_VERSION = 1


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def read_udp_frame_from_tls(reader: asyncio.StreamReader) -> tuple[str, int, bytes, int]:
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


def pack_udp_frame(host: str, port: int, data: bytes) -> bytes:
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


class UdpRelayProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        tls_writer: asyncio.StreamWriter,
        write_lock: asyncio.Lock,
        stats: SessionStats,
    ):
        self._tls_writer = tls_writer
        self._write_lock = write_lock
        self._stats = stats
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not isinstance(addr, tuple) or len(addr) < 2:
            return
        host, port = str(addr[0]), int(addr[1])
        try:
            frame = pack_udp_frame(host, port, data)
        except ValueError:
            return

        async def _send() -> None:
            async with self._write_lock:
                self._stats.download_bytes += len(frame)
                self._tls_writer.write(frame)
                await self._tls_writer.drain()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(_send())

    def error_received(self, exc: Exception) -> None:
        LOG.debug("udp relay socket error: %s", exc)


async def pipe_tls_to_udp(
    reader: asyncio.StreamReader,
    transport: asyncio.DatagramTransport,
    stats: SessionStats,
    fixed_host: Optional[str],
    fixed_port: Optional[int],
) -> None:
    try:
        while True:
            host, port, data, wire_len = await read_udp_frame_from_tls(reader)
            if fixed_host is not None:
                host, port = fixed_host, fixed_port  # type: ignore[assignment]
            transport.sendto(data, (host, port))
            stats.upload_bytes += wire_len
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        transport.close()


async def run_udp_relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stats: SessionStats,
    host: str,
    port: int,
) -> None:
    loop = asyncio.get_running_loop()
    write_lock = asyncio.Lock()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: UdpRelayProtocol(writer, write_lock, stats),
        local_addr=("0.0.0.0", 0),
    )
    assert isinstance(transport, asyncio.DatagramTransport)

    fixed: tuple[Optional[str], Optional[int]]
    if host == "0.0.0.0" and port == 0:
        fixed = (None, None)
    else:
        fixed = (host, port)

    writer.write(b"OK\n")
    await writer.drain()

    await pipe_tls_to_udp(reader, transport, stats, fixed[0], fixed[1])


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    allowed_tokens: set[str],
    allow_networks: list[ipaddress._BaseNetwork],
    connect_timeout: float,
    bootstrap_timeout: float = 30.0,
) -> None:
    session_id = uuid.uuid4().hex[:8]
    peer = writer.get_extra_info("peername")
    stats = SessionStats()
    target_writer: Optional[asyncio.StreamWriter] = None
    _set_socket_options(writer, enable_keepalive=True)
    try:
        if not peer_allowed(peer, allow_networks):
            raise PermissionError("peer not in allow-cidrs")

        line = await asyncio.wait_for(reader.readline(), timeout=bootstrap_timeout)
        if not line:
            raise ValueError("empty bootstrap")

        host, port, proto = parse_bootstrap_line(line, allowed_tokens)
        LOG.info(
            "[sid=%s] accepted tunnel from %s to %s:%s (%s)",
            session_id,
            peer,
            host,
            port,
            proto,
        )

        if proto == "udp":
            await run_udp_relay(reader, writer, stats, host, port)
        else:
            t0 = time.perf_counter()
            # DNS cache lookup (transplanted from Go impl)
            cached_ip = await _dns_cache.resolve(host)
            if cached_ip is None:
                raise OSError(f"DNS resolution failed for {host}")
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(cached_ip, port),
                timeout=connect_timeout,
            )
            _set_socket_options(target_writer)
            t1 = time.perf_counter()
            LOG.debug(
                "[sid=%s] backend connect timing: %.0fms to %s:%s (timeout=%.1fs), dns=%s",
                session_id,
                (t1 - t0) * 1000.0,
                host,
                port,
                connect_timeout,
                cached_ip,
            )

            writer.write(b"OK\n")
            await writer.drain()

            await asyncio.gather(
                pipe(reader, target_writer, stats, True),
                pipe(target_reader, writer, stats, False),
            )
    except AuthError:
        LOG.warning("[sid=%s] auth failed from %s", session_id, peer)
        try:
            writer.write(b"ERR auth\n")
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
    except (
        PermissionError,
        ValueError,
        asyncio.IncompleteReadError,
        TimeoutError,
        asyncio.TimeoutError,
        ConnectionError,
        OSError,
        ssl.SSLError,
    ) as exc:
        LOG.warning("[sid=%s] connection failed from %s: %s", session_id, peer, exc)
        try:
            writer.write(b"ERR connect\n")
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
    finally:
        LOG.info(
            "[sid=%s] session closed from %s (up=%s bytes, down=%s bytes)",
            session_id,
            peer,
            stats.upload_bytes,
            stats.download_bytes,
        )
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TLS tunnel proxy server for Linux deployment"
    )
    parser.add_argument("--listen", default=os.getenv("VPN_PROXY_LISTEN", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("VPN_PROXY_PORT", "8443")),
    )
    parser.add_argument(
        "--cert",
        default=os.getenv("VPN_PROXY_CERT", "./certs/server.crt"),
        help="TLS certificate path",
    )
    parser.add_argument(
        "--key",
        default=os.getenv("VPN_PROXY_KEY", "./certs/server.key"),
        help="TLS private key path",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("VPN_PROXY_TOKEN"),
        help="shared token; env VPN_PROXY_TOKEN is supported",
    )
    parser.add_argument(
        "--tokens-file",
        default=os.getenv("VPN_PROXY_TOKENS_FILE"),
        help="optional file with one token per line",
    )
    parser.add_argument(
        "--allow-cidrs",
        default=os.getenv("VPN_PROXY_ALLOW_CIDRS", ""),
        help="comma-separated client IP CIDRs, e.g. 1.2.3.4/32,10.0.0.0/8",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=float(os.getenv("VPN_PROXY_CONNECT_TIMEOUT", "8")),
    )
    parser.add_argument(
        "--bootstrap-timeout",
        type=float,
        default=float(os.getenv("VPN_PROXY_BOOTSTRAP_TIMEOUT", "30")),
        help="seconds to wait for client bootstrap line (env VPN_PROXY_BOOTSTRAP_TIMEOUT)",
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=int(os.getenv("VPN_PROXY_BACKLOG", "512")),
        help="listen backlog size (env VPN_PROXY_BACKLOG)",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("VPN_PROXY_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


async def main_async(args: argparse.Namespace) -> None:
    allowed_tokens = load_allowed_tokens(args)
    if not allowed_tokens:
        raise SystemExit("missing token(s): set --token, --tokens-file or env var")
    allow_networks = parse_allow_cidrs(args.allow_cidrs)
    if allow_networks:
        LOG.info("allow-cidrs enabled with %d network(s)", len(allow_networks))

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ssl_ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        )
    except ssl.SSLError:
        pass

    server = await asyncio.start_server(
        lambda r, w: handle_client(
            r, w, allowed_tokens, allow_networks, args.connect_timeout,
            bootstrap_timeout=args.bootstrap_timeout,
        ),
        host=args.listen,
        port=args.port,
        ssl=ssl_ctx,
        backlog=args.backlog,
    )

    sockets = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    LOG.info("server started on %s", sockets)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        LOG.info("uvloop enabled")
    except ImportError:
        pass
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
