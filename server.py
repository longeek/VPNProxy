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

from vpn_proxy_frame import UDP_FRAME_VERSION, pack_udp_frame, read_exact, read_udp_frame


LOG = logging.getLogger("vpn-proxy-server")


class AuthError(Exception):
    pass


class _RateLimiter:
    """Token-bucket rate limiter (transplanted from Go implementation).

    Default: 100 tokens/sec, burst of 20 connections.
    Thread-safe via threading.Lock for use across async tasks.
    """

    def __init__(self, rate_per_sec: float = 100.0, burst: int = 20) -> None:
        self._rate = rate_per_sec
        self._max_tokens = burst
        self._tokens = burst
        self._last_refill = time.monotonic()
        self._lock = __import__("threading").Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            new_tokens = int(elapsed * self._rate)
            if new_tokens > 0:
                self._tokens = min(self._tokens + new_tokens, self._max_tokens)
                self._last_refill = now
            if self._tokens > 0:
                self._tokens -= 1
                return True
            return False


_conn_limiter = _RateLimiter()


class _BufPool:
    """Pre-allocated buffer pool for zero-copy UDP frame construction.

    Reduces allocation pressure in the hot UDP datagram forwarding path by
    reusing a fixed set of buffers. Thread-safe via threading.Lock for use
    across async tasks.

    Buffer layout: each buffer is sized to hold the maximum datagram (65535
    bytes) plus maximum frame header (~1032 bytes for a 1024-byte hostname).
    """

    __slots__ = ("_pool", "_available", "_lock")
    _BUF_SIZE = 65536 + 2048  # max datagram + max frame header reserve

    def __init__(self, pool_size: int = 64) -> None:
        self._pool: list[bytearray] = [
            bytearray(self._BUF_SIZE) for _ in range(pool_size)
        ]
        self._available: list[int] = list(range(pool_size))
        self._lock = __import__("threading").Lock()

    def acquire(self) -> tuple[int, bytearray]:
        """Get a buffer index and the buffer itself.

        Call :meth:`release` with the index when done to return the buffer
        to the pool. If the pool is empty it will grow dynamically.
        """
        with self._lock:
            if not self._available:
                idx = len(self._pool)
                self._pool.append(bytearray(self._BUF_SIZE))
            else:
                idx = self._available.pop()
        return idx, self._pool[idx]

    def release(self, idx: int) -> None:
        """Return a buffer to the pool by its index."""
        with self._lock:
            self._available.append(idx)


# Global buffer pool for zero-copy UDP frame construction
_udp_buf_pool = _BufPool()


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


class TlsSessionStore:
    """Pre-created TLS session pool to reduce handshake overhead.

    Maintains a pool of pre-configured SSL context objects for reuse
    across outgoing backend connections. When a host:port is provided,
    sessions are pre-warmed by establishing a TLS handshake to cache the
    session for potential resumption. Otherwise, contexts are pre-configured
    with the project's cipher and TLS version settings.

    Thread-safe via asyncio.Lock. A background task periodically replenishes
    the pool based on *refresh_interval*.
    """

    def __init__(
        self,
        host: str = "",
        port: int = 0,
        pool_size: int = 3,
        refresh_interval: float = 60.0,
    ) -> None:
        self._host = host
        self._port = port
        self._pool_size = pool_size
        self._refresh_interval = refresh_interval
        self._sessions: asyncio.Queue[ssl.SSLContext] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._closed = False
        self._refill_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Pre-create TLS sessions and start the background refill loop."""
        for _ in range(self._pool_size):
            ctx = await self._create_session()
            await self._sessions.put(ctx)
        LOG.debug(
            "pre-warmed %d TLS sessions for %s:%s",
            self._pool_size,
            self._host or "<dynamic>",
            self._port,
        )
        self._refill_task = asyncio.create_task(self._refill_loop())

    async def get_session(self) -> Optional[ssl.SSLContext]:
        """Return a pre-warmed TLS context, or None if the pool is empty.

        This is a non-blocking call. If no session is available the caller
        should fall back to creating a fresh :class:`ssl.SSLContext`.
        """
        try:
            return self._sessions.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def _create_session(self) -> ssl.SSLContext:
        """Create a single TLS context, optionally pre-warming the session.

        If *host* was provided to the constructor a full TLS handshake is
        performed so the TLS session is cached in the context (enabling
        session resumption on subsequent connections). On failure the
        context is still returned — it simply has no cached session.
        """
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:"
                "!aNULL:!MD5:!DSS"
            )
        except ssl.SSLError:
            pass

        if self._host:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port, ssl=ctx),
                    timeout=10.0,
                )
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
                LOG.debug(
                    "failed to pre-warm TLS session for %s:%s: %s",
                    self._host,
                    self._port,
                    exc,
                )
        return ctx

    async def _refill_loop(self) -> None:
        """Background task that replenishes the pool periodically."""
        while not self._closed:
            await asyncio.sleep(self._refresh_interval)
            try:
                need = self._pool_size - self._sessions.qsize()
                if need > 0:
                    LOG.debug("refilling TLS session pool (%d needed)", need)
                    for _ in range(need):
                        ctx = await self._create_session()
                        await self._sessions.put(ctx)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(1.0)

    async def close(self) -> None:
        """Shut down the background refill task and mark the pool closed."""
        self._closed = True
        if self._refill_task is not None:
            self._refill_task.cancel()
            try:
                await self._refill_task
            except asyncio.CancelledError:
                pass


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


# UDP_FRAME_VERSION, pack_udp_frame, read_exact, read_udp_frame
# are imported from vpn_proxy_frame.py (shared with client.py)


def _pack_udp_frame_fast(host: str, port: int, data: bytes, buf: bytearray) -> memoryview:
    """Pack a UDP frame into *buf* using zero-copy memoryview writes.

    Builds the frame header directly into the pre-allocated *buf* via
    ``memoryview`` slice assignments, then copies the data payload in a
    single write — no intermediate ``bytes`` objects are created.

    Returns a ``memoryview`` slice referencing only the used portion of
    *buf*.  The caller is responsible for ensuring no other reference to
    *buf* exists during this call.

    Raises ``ValueError`` if the host or datagram exceed protocol limits,
    or if *buf* is too small for the resulting frame.
    """
    hb = host.encode("utf-8")
    hb_len = len(hb)
    if hb_len > 1024:
        raise ValueError("host too long")
    data_len = len(data)
    if data_len > 65535:
        raise ValueError("datagram too large")

    # Frame layout: ver(1) + rsv(1) + host_len(2) + host(N) + port(2) + dlen(2) + payload
    header_len = 4 + hb_len + 4
    total_len = header_len + data_len

    if total_len > len(buf):
        raise ValueError("buffer too small")

    mv = memoryview(buf)
    # Bytes 0-3: version, reserved, host length (big-endian)
    mv[0] = UDP_FRAME_VERSION
    mv[1] = 0
    mv[2:4] = hb_len.to_bytes(2, "big")
    # Bytes 4 .. 4+hb_len-1: hostname (UTF-8)
    mv[4:4+hb_len] = hb
    # Bytes 4+hb_len .. 4+hb_len+3: port + datagram length (big-endian)
    mv[4+hb_len:header_len] = struct.pack("!HH", port, data_len)
    # Bytes header_len .. total_len-1: datagram payload
    mv[header_len:total_len] = data

    return mv[:total_len]


class UdpRelayProtocol(asyncio.DatagramProtocol):
    """Zero-copy UDP relay protocol with pre-allocated buffer pool.

    Instead of spawning one asyncio task per datagram (current behaviour),
    this implementation uses a dedicated sender loop with an internal queue.
    Frames are constructed with ``memoryview`` into a reusable buffer pool,
    avoiding intermediate ``bytes`` allocations in the hot path.
    """

    def __init__(
        self,
        tls_writer: asyncio.StreamWriter,
        write_lock: asyncio.Lock,
        stats: SessionStats,
        buf_pool: _BufPool = _udp_buf_pool,
    ):
        self._tls_writer = tls_writer
        self._write_lock = write_lock
        self._stats = stats
        self._buf_pool = buf_pool
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._queue: asyncio.Queue[tuple[bytes, object]] = asyncio.Queue()
        self._sender_task: Optional[asyncio.Task] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._sender_task = asyncio.create_task(self._sender_loop())

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._sender_task is not None:
            self._sender_task.cancel()

    def datagram_received(self, data: bytes, addr: object) -> None:
        """Queue a received datagram for framing and TLS forwarding.

        This runs synchronously in the event-loop thread and must not
        block.  The actual frame construction and I/O happens in the
        dedicated ``_sender_loop`` task.
        """
        self._queue.put_nowait((data, addr))

    async def _sender_loop(self) -> None:
        """Dedicated sender: processes queued datagrams in a tight loop.

        Uses the pre-allocated buffer pool and ``memoryview``-based frame
        construction to minimise allocation in the hot path.
        """
        while True:
            try:
                data, addr = await self._queue.get()
            except asyncio.CancelledError:
                return

            if not isinstance(addr, tuple) or len(addr) < 2:
                continue
            host, port = str(addr[0]), int(addr[1])

            # Acquire a buffer from the pre-allocated pool
            idx, buf = self._buf_pool.acquire()
            try:
                frame_mv = _pack_udp_frame_fast(host, port, data, buf)
                async with self._write_lock:
                    self._stats.download_bytes += len(frame_mv)
                    self._tls_writer.write(frame_mv)
                    await self._tls_writer.drain()
            except ValueError:
                pass
            finally:
                self._buf_pool.release(idx)

    def error_received(self, exc: Exception) -> None:
        LOG.debug("udp relay socket error: %s", exc)


async def pipe_tls_to_udp(
    reader: asyncio.StreamReader,
    transport: asyncio.DatagramTransport,
    stats: SessionStats,
    fixed_host: Optional[str],
    fixed_port: Optional[int],
) -> None:
    """Read framed UDP datagrams from *reader* and forward via *transport*.

    The ``transport.sendto`` call is already a direct socket send (no
    intermediate bytearray copy).  This function is kept clean since the
    hot-path allocation is dominated by the TLS decryption in
    ``read_udp_frame`` which we cannot bypass.
    """
    try:
        while True:
            host, port, data, wire_len = await read_udp_frame(reader)
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
    buf_pool: _BufPool = _udp_buf_pool,
) -> None:
    """Set up UDP relay with zero-copy buffer pool.

    Creates a ``DatagramTransport`` for receiving remote UDP datagrams and
    uses the pre-allocated buffer pool + dedicated sender loop for framing
    and forwarding.
    """
    loop = asyncio.get_running_loop()
    write_lock = asyncio.Lock()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: UdpRelayProtocol(writer, write_lock, stats, buf_pool),
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
    tls_session_store: Optional[TlsSessionStore] = None,
) -> None:
    session_id = uuid.uuid4().hex[:8]
    peer = writer.get_extra_info("peername")
    stats = SessionStats()
    target_writer: Optional[asyncio.StreamWriter] = None
    _set_socket_options(writer, enable_keepalive=True)

    if not _conn_limiter.allow():
        LOG.warning("[sid=%s] rate limit exceeded from %s", session_id, peer)
        try:
            writer.write(b"ERR rate limit\n")
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
        return

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
            ssl_ctx: Optional[ssl.SSLContext] = None
            if tls_session_store is not None:
                ssl_ctx = await tls_session_store.get_session()
                if ssl_ctx is None:
                    # Fallback: create a fresh context on the fly
                    ssl_ctx = ssl.create_default_context(
                        ssl.Purpose.SERVER_AUTH
                    )
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    try:
                        ssl_ctx.set_ciphers(
                            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:"
                            "DHE+CHACHA20:!aNULL:!MD5:!DSS"
                        )
                    except ssl.SSLError:
                        pass

            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    cached_ip, port, ssl=ssl_ctx,
                ),
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
        "--backend-tls",
        action="store_true",
        default=False,
        help="enable TLS for backend outbound connections",
    )
    parser.add_argument(
        "--backend-tls-pool",
        type=int,
        default=int(os.getenv("VPN_PROXY_BACKEND_TLS_POOL", "3")),
        help="TLS session pool size (env VPN_PROXY_BACKEND_TLS_POOL, default: 3)",
    )
    parser.add_argument(
        "--backend-tls-refresh",
        type=float,
        default=float(os.getenv("VPN_PROXY_BACKEND_TLS_REFRESH", "60")),
        help="TLS session pool refresh interval in seconds "
        "(env VPN_PROXY_BACKEND_TLS_REFRESH, default: 60)",
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

    # TLS session store for pre-warmed backend connections (optional)
    tls_session_store: Optional[TlsSessionStore] = None
    if args.backend_tls:
        tls_session_store = TlsSessionStore(
            pool_size=args.backend_tls_pool,
            refresh_interval=args.backend_tls_refresh,
        )
        await tls_session_store.start()
        LOG.info(
            "backend TLS enabled with pool size %d, refresh %.0fs",
            args.backend_tls_pool,
            args.backend_tls_refresh,
        )

    server = await asyncio.start_server(
        lambda r, w: handle_client(
            r, w, allowed_tokens, allow_networks, args.connect_timeout,
            bootstrap_timeout=args.bootstrap_timeout,
            tls_session_store=tls_session_store,
        ),
        host=args.listen,
        port=args.port,
        ssl=ssl_ctx,
        backlog=args.backlog,
    )

    sockets = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    LOG.info("server started on %s", sockets)
    try:
        async with server:
            await server.serve_forever()
    finally:
        if tls_session_store is not None:
            await tls_session_store.close()


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
