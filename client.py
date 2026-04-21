#!/usr/bin/env python3
import argparse
import asyncio
import base64
import collections
import errno
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import time
import uuid
from typing import Optional


LOG = logging.getLogger("vpn-proxy-client")


SOCKS_VERSION = 5

_RECV_BUF = 256 * 1024


def _set_socket_options(writer: asyncio.StreamWriter) -> None:
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


class SocksProtocolError(ValueError):
    def __init__(self, message: str, reply_code: int):
        super().__init__(message)
        self.reply_code = reply_code


class TunnelAuthError(ConnectionError):
    pass


class TunnelBackendError(ConnectionError):
    pass


class HttpProxyError(ValueError):
    pass


class TcpLineTargetError(ValueError):
    pass


class ProxyAuthError(ValueError):
    pass


UDP_FRAME_VERSION = 1


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    drain_threshold = 128 * 1024
    pending = 0
    try:
        while True:
            data = await reader.read(131072)
            if not data:
                break
            if writer.is_closing():
                break
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


async def read_exact(reader: asyncio.StreamReader, size: int) -> bytes:
    data = await reader.readexactly(size)
    return data


async def socks5_read_address(
    reader: asyncio.StreamReader, atyp: int
) -> tuple[str, int]:
    if atyp == 0x01:  # IPv4
        addr = await read_exact(reader, 4)
        host = socket.inet_ntop(socket.AF_INET, addr)
    elif atyp == 0x03:  # Domain
        ln = (await read_exact(reader, 1))[0]
        host = (await read_exact(reader, ln)).decode("utf-8", errors="ignore")
    elif atyp == 0x04:  # IPv6
        addr = await read_exact(reader, 16)
        host = socket.inet_ntop(socket.AF_INET6, addr)
    else:
        raise SocksProtocolError("unsupported ATYP", 0x08)

    port = int.from_bytes(await read_exact(reader, 2), "big")
    return host, port


async def socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy_user: Optional[str] = None,
    proxy_pass: Optional[str] = None,
) -> tuple[str, int, int]:
    header = await read_exact(reader, 2)
    ver, nmethods = header[0], header[1]
    if ver != SOCKS_VERSION:
        raise SocksProtocolError("unsupported SOCKS version", 0x01)

    methods = await read_exact(reader, nmethods)
    require_auth = proxy_user is not None
    if require_auth:
        if 0x02 not in methods:
            writer.write(bytes([SOCKS_VERSION, 0xFF]))
            await writer.drain()
            raise SocksProtocolError("proxy requires auth but client did not offer method 0x02", 0xFF)
        writer.write(bytes([SOCKS_VERSION, 0x02]))
        await writer.drain()
        auth_ver = (await read_exact(reader, 1))[0]
        if auth_ver != 0x01:
            raise SocksProtocolError("unsupported SOCKS auth sub-negotiation version", 0xFF)
        ulen = (await read_exact(reader, 1))[0]
        username = (await read_exact(reader, ulen)).decode("utf-8", errors="replace")
        plen = (await read_exact(reader, 1))[0]
        password = (await read_exact(reader, plen)).decode("utf-8", errors="replace")
        if username != proxy_user or password != proxy_pass:
            writer.write(bytes([0x01, 0x01]))
            await writer.drain()
            raise SocksProtocolError("SOCKS auth failed", 0x02)
        writer.write(bytes([0x01, 0x00]))
        await writer.drain()
    else:
        if 0x00 not in methods:
            writer.write(bytes([SOCKS_VERSION, 0xFF]))
            await writer.drain()
            raise SocksProtocolError("no acceptable auth method", 0xFF)
        writer.write(bytes([SOCKS_VERSION, 0x00]))
        await writer.drain()

    req_header = await read_exact(reader, 4)
    ver, cmd, _rsv, atyp = req_header
    if ver != SOCKS_VERSION or cmd not in (0x01, 0x03):
        raise SocksProtocolError("unsupported command", 0x07)

    host, port = await socks5_read_address(reader, atyp)
    return host, port, cmd


async def send_socks_reply(writer: asyncio.StreamWriter, rep: int) -> None:
    writer.write(bytes([SOCKS_VERSION, rep, 0x00, 0x01]) + b"\x00\x00\x00\x00\x00\x00")
    await writer.drain()


async def send_socks_reply_bound(
    writer: asyncio.StreamWriter, rep: int, bind_host: str, bind_port: int
) -> None:
    try:
        packed = ipaddress.ip_address(bind_host).packed
    except ValueError:
        hb = bind_host.encode("utf-8")
        if len(hb) > 255:
            raise SocksProtocolError("bind host too long", 0x01)
        body = bytes([SOCKS_VERSION, rep, 0x00, 0x03, len(hb)]) + hb + bind_port.to_bytes(
            2, "big"
        )
        writer.write(body)
        await writer.drain()
        return
    if len(packed) == 4:
        atyp = 0x01
    elif len(packed) == 16:
        atyp = 0x04
    else:
        raise SocksProtocolError("unsupported bind address", 0x08)
    writer.write(
        bytes([SOCKS_VERSION, rep, 0x00, atyp]) + packed + bind_port.to_bytes(2, "big")
    )
    await writer.drain()


def build_tls_context(
    ca_cert: Optional[str],
    insecure: bool,
) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
            )
        except ssl.SSLError:
            pass
        return ctx

    if ca_cert:
        ctx = ssl.create_default_context(cafile=ca_cert)
    else:
        ctx = ssl.create_default_context()
    try:
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        )
    except ssl.SSLError:
        pass
    return ctx


def resolve_tunnel_tls(args: argparse.Namespace) -> tuple[ssl.SSLContext, Optional[str]]:
    ssl_ctx: Optional[ssl.SSLContext] = getattr(args, "_vpn_proxy_ssl_ctx", None)
    if ssl_ctx is None:
        ssl_ctx = build_tls_context(args.ca_cert, args.insecure)
        setattr(args, "_vpn_proxy_ssl_ctx", ssl_ctx)

    server_name = args.sni or (None if args.insecure else args.server)
    return ssl_ctx, server_name


class TunnelPool:
    """Pre-established TLS connection pool to reduce tunnel setup latency."""

    def __init__(self, args: argparse.Namespace, max_size: int = 2, ttl: float = 8.0):
        self._args = args
        self._max_size = max_size
        self._ttl = ttl
        self._pool: list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = []
        self._lock = asyncio.Lock()
        self._closed = False
        self._refill_task: Optional[asyncio.Task] = None
        self._hits = 0

    async def start(self) -> None:
        self._closed = False
        for _ in range(self._max_size):
            try:
                r, w = await self._create_tls_connection()
                self._pool.append((r, w, time.monotonic()))
            except (ConnectionError, OSError, ssl.SSLError):
                break
        self._refill_task = asyncio.create_task(self._refill_loop())

    async def stop(self) -> None:
        self._closed = True
        if self._refill_task is not None:
            self._refill_task.cancel()
            try:
                await self._refill_task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            while self._pool:
                _, writer, _ = self._pool.pop()
                try:
                    writer.close()
                    await writer.wait_closed()
                except (ConnectionError, OSError, RuntimeError):
                    pass
        if self._hits:
            LOG.info("tunnel pool stopped (pool_hits=%d)", self._hits)

    async def _create_tls_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ssl_ctx, server_name = resolve_tunnel_tls(self._args)
        reader, writer = await asyncio.open_connection(
            host=self._args.server,
            port=self._args.server_port,
            ssl=ssl_ctx,
            server_hostname=server_name,
        )
        _set_socket_options(writer)
        return reader, writer

    async def _refill_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(0.3)
            try:
                expired = []
                async with self._lock:
                    now = time.monotonic()
                    fresh = []
                    for item in self._pool:
                        if (now - item[2]) > self._ttl:
                            expired.append(item)
                        else:
                            fresh.append(item)
                    self._pool = fresh
                for _, w, _ in expired:
                    try:
                        w.close()
                        await w.wait_closed()
                    except (ConnectionError, OSError, RuntimeError):
                        pass
                need = 0
                async with self._lock:
                    need = self._max_size - len(self._pool)
                if need > 0:
                    try:
                        r, w = await self._create_tls_connection()
                        async with self._lock:
                            self._pool.append((r, w, time.monotonic()))
                    except (ConnectionError, OSError, ssl.SSLError) as exc:
                        LOG.debug("pool refill failed: %s", exc)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(1.0)

    async def acquire(
        self,
    ) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        to_close: list[asyncio.StreamWriter] = []
        found = None
        async with self._lock:
            while self._pool:
                reader, writer, created = self._pool.pop(0)
                if (time.monotonic() - created) < self._ttl and not reader.at_eof():
                    found = (reader, writer)
                    self._hits += 1
                    break
                to_close.append(writer)
        for w in to_close:
            try:
                w.close()
                await w.wait_closed()
            except (ConnectionError, OSError, RuntimeError):
                pass
        return found


def map_socks_reply(exc: BaseException) -> int:
    if isinstance(exc, SocksProtocolError):
        return exc.reply_code
    if isinstance(exc, TunnelAuthError):
        return 0x02  # connection not allowed by ruleset
    if isinstance(exc, ConnectionRefusedError):
        return 0x05
    if isinstance(exc, (socket.gaierror, TimeoutError, asyncio.TimeoutError)):
        return 0x04
    if isinstance(exc, OSError):
        if exc.errno in {errno.ENETUNREACH, 10051}:
            return 0x03
        if exc.errno in {errno.EHOSTUNREACH, 10065}:
            return 0x04
        if exc.errno in {errno.ECONNREFUSED, 10061}:
            return 0x05
    return 0x01


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


async def read_udp_tunnel_frame(reader: asyncio.StreamReader) -> tuple[str, int, bytes]:
    ver_rsv_nlen = await read_exact(reader, 4)
    ver, _rsv, nlen = ver_rsv_nlen[0], ver_rsv_nlen[1], int.from_bytes(ver_rsv_nlen[2:4], "big")
    if ver != UDP_FRAME_VERSION:
        raise ValueError("bad udp frame version")
    if nlen == 0 or nlen > 1024:
        raise ValueError("bad udp frame host length")
    host = (await read_exact(reader, nlen)).decode("utf-8", errors="replace")
    port_dlen = await read_exact(reader, 4)
    port, dlen = struct.unpack("!HH", port_dlen)
    if dlen > 65535:
        raise ValueError("bad udp frame payload length")
    data = await read_exact(reader, dlen) if dlen else b""
    return host, port, data


def socks_udp_parse_request(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 10:
        raise ValueError("short socks udp packet")
    rsv_hi, rsv_lo, frag, atyp = packet[0], packet[1], packet[2], packet[3]
    if rsv_hi != 0 or rsv_lo != 0 or frag != 0:
        raise ValueError("bad socks udp header")
    off = 4
    if atyp == 0x01:
        if len(packet) < off + 6:
            raise ValueError("short ipv4")
        host = socket.inet_ntop(socket.AF_INET, packet[off : off + 4])
        off += 4
    elif atyp == 0x03:
        if off >= len(packet):
            raise ValueError("short domain")
        ln = packet[off]
        off += 1
        if len(packet) < off + ln + 2:
            raise ValueError("short domain body")
        host = packet[off : off + ln].decode("utf-8", errors="replace")
        off += ln
    elif atyp == 0x04:
        if len(packet) < off + 18:
            raise ValueError("short ipv6")
        host = socket.inet_ntop(socket.AF_INET6, packet[off : off + 16])
        off += 16
    else:
        raise ValueError("unsupported socks udp atyp")
    port = int.from_bytes(packet[off : off + 2], "big")
    off += 2
    return host, port, packet[off:]


def socks_udp_build_reply(host: str, port: int, data: bytes) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        hb = host.encode("utf-8")
        if len(hb) > 255:
            raise ValueError("reply host too long")
        head = b"\x00\x00\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big")
        return head + data
    if ip.version == 4:
        head = b"\x00\x00\x00\x01" + ip.packed + port.to_bytes(2, "big")
        return head + data
    head = b"\x00\x00\x00\x04" + ip.packed + port.to_bytes(2, "big")
    return head + data


async def open_tunnel(
    target_host: str,
    target_port: int,
    args: argparse.Namespace,
    session_id: str,
    *,
    proto: str = "tcp",
    pool: Optional[TunnelPool] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if pool is not None:
        try:
            conn = await pool.acquire()
            if conn is not None:
                reader, writer = conn
                payload: dict = {
                    "auth": args.token,
                    "host": target_host,
                    "port": target_port,
                }
                if proto != "tcp":
                    payload["proto"] = proto
                bootstrap = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
                writer.write(bootstrap)
                await writer.drain()
                try:
                    status = await asyncio.wait_for(reader.readline(), timeout=10)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
                    status = b""
                if status.startswith(b"OK"):
                    LOG.info("[sid=%s] tunnel from pool (saved TLS handshake)", session_id)
                    return reader, writer
                try:
                    writer.close()
                    await writer.wait_closed()
                except (ConnectionError, OSError, RuntimeError):
                    pass
        except (ConnectionError, OSError, ssl.SSLError):
            pass

    last_exc: Optional[Exception] = None
    retries = max(0, args.connect_retries)
    ssl_ctx, server_name = resolve_tunnel_tls(args)
    for attempt in range(retries + 1):
        try:
            t0 = time.perf_counter()
            reader, writer = await asyncio.open_connection(
                host=args.server,
                port=args.server_port,
                ssl=ssl_ctx,
                server_hostname=server_name,
            )
            _set_socket_options(writer)
            t1 = time.perf_counter()

            payload: dict = {
                "auth": args.token,
                "host": target_host,
                "port": target_port,
            }
            if proto != "tcp":
                payload["proto"] = proto
            bootstrap = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
            writer.write(bootstrap)
            await writer.drain()

            status = await asyncio.wait_for(reader.readline(), timeout=10)
            t2 = time.perf_counter()
            if not status.startswith(b"OK"):
                writer.close()
                await writer.wait_closed()
                status_text = status.decode(errors="replace").strip()
                if status.startswith(b"ERR auth"):
                    raise TunnelAuthError(f"proxy server refused auth: {status_text}")
                raise TunnelBackendError(f"proxy server refused: {status_text}")

            if attempt > 0:
                LOG.info("[sid=%s] tunnel recovered after retry %s", session_id, attempt)
            LOG.debug(
                "[sid=%s] tunnel timings: tls_connect=%.0fms, bootstrap_rtt=%.0fms (proto=%s -> %s:%s via %s:%s)",
                session_id,
                (t1 - t0) * 1000.0,
                (t2 - t1) * 1000.0,
                proto,
                target_host,
                target_port,
                args.server,
                args.server_port,
            )
            return reader, writer
        except (
            ConnectionError,
            OSError,
            ssl.SSLError,
            TimeoutError,
            asyncio.TimeoutError,
        ) as exc:
            last_exc = exc
            if attempt >= retries:
                break
            delay = max(0.1, args.retry_delay * (2 ** attempt))
            LOG.warning(
                "[sid=%s] tunnel connect failed (%s), retrying in %.1fs [%s/%s]",
                session_id,
                exc,
                delay,
                attempt + 1,
                retries,
            )
            await asyncio.sleep(delay)

    raise ConnectionError(f"unable to open tunnel: {last_exc}")


def parse_http_connect_target(header_block: bytes) -> tuple[str, int]:
    lines = header_block.split(b"\r\n", 1)
    if not lines or not lines[0]:
        raise HttpProxyError("empty request")
    first = lines[0].decode("latin-1", errors="replace").strip()
    m = re.match(r"^CONNECT\s+(.+)\s+HTTP/\d", first, re.I)
    if not m:
        raise HttpProxyError("not a CONNECT request")
    target = m.group(1).strip()
    if target.startswith("["):
        if "]:" not in target:
            raise HttpProxyError("bad IPv6 target")
        host, _, port_s = target.rpartition("]:")
        host = host[1:]
        port = int(port_s)
    else:
        if target.count(":") != 1:
            raise HttpProxyError("bad target (use host:port or [ipv6]:port)")
        host, port_s = target.rsplit(":", 1)
        if not port_s.isdigit():
            raise HttpProxyError("bad port")
        port = int(port_s)
    if port < 1 or port > 65535:
        raise HttpProxyError("bad port")
    if not host:
        raise HttpProxyError("empty host")
    return host, port


def parse_tcp_line_target(line: bytes) -> tuple[str, int]:
    s = line.strip().decode("utf-8", errors="replace")
    if not s:
        raise TcpLineTargetError("empty target line")
    if ":" in s:
        host, _, ps = s.rpartition(":")
        host = host.strip()
        if not host or not ps.strip().isdigit():
            raise TcpLineTargetError("expected host:port")
        port = int(ps.strip())
    else:
        parts = s.split()
        if len(parts) != 2 or not parts[1].isdigit():
            raise TcpLineTargetError("expected 'host:port' or 'host port'")
        host, port = parts[0], int(parts[1])
    if port < 1 or port > 65535:
        raise TcpLineTargetError("bad port")
    return host, port


async def handle_socks_udp_relay(
    client_tcp_reader: asyncio.StreamReader,
    client_tcp_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    session_id: str,
    *,
    pool: Optional[TunnelPool] = None,
) -> None:
    """SOCKS5 UDP ASSOCIATE: SOCKS UDP header per datagram; replies matched by (dst host, dst port)."""
    loop = asyncio.get_running_loop()
    tunnel_reader, tunnel_writer = await open_tunnel(
        "0.0.0.0", 0, args, session_id, proto="udp", pool=pool
    )
    pending: dict[tuple[str, int], list[tuple[tuple[str, int], str, int]]] = {}
    pending_lock = asyncio.Lock()
    tunnel_write_lock = asyncio.Lock()

    async def tunnel_to_udp(tudp: asyncio.DatagramTransport) -> None:
        try:
            while True:
                try:
                    rh, rp, rdata = await read_udp_tunnel_frame(tunnel_reader)
                except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
                    break
                try:
                    pkt = socks_udp_build_reply(rh, rp, rdata)
                except ValueError:
                    continue
                key = (rh, rp)
                async with pending_lock:
                    entries = pending.pop(key, None)
                    if entries is None:
                        continue
                    client_addr = entries.pop(0)[0]
                    if entries:
                        pending[key] = entries
                tudp.sendto(pkt, client_addr)
        finally:
            pass

    async def forward_app_datagram(data: bytes, src_addr: tuple[str, int]) -> None:
        try:
            h, p, payload = socks_udp_parse_request(data)
            frame = pack_udp_frame(h, p, payload)
        except ValueError:
            return
        async with pending_lock:
            key = (h, p)
            li = pending.setdefault(key, [])
            li.append((src_addr, h, p))
        try:
            async with tunnel_write_lock:
                tunnel_writer.write(frame)
                await tunnel_writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass

    class SocksUdpFrontend(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not isinstance(addr, tuple) or len(addr) < 2:
                return
            src = (str(addr[0]), int(addr[1]))
            loop.create_task(forward_app_datagram(data, src))

    transport, _ = await loop.create_datagram_endpoint(
        SocksUdpFrontend, local_addr=(args.listen, 0)
    )
    assert isinstance(transport, asyncio.DatagramTransport)
    sockname = transport.get_extra_info("sockname")
    if not isinstance(sockname, tuple) or len(sockname) < 2:
        raise SocksProtocolError("udp bind failed", 0x01)
    bind_port = int(sockname[1])
    bind_ip = str(sockname[0])
    reply_host = "127.0.0.1" if bind_ip in ("0.0.0.0", "::") else bind_ip
    await send_socks_reply_bound(client_tcp_writer, 0x00, reply_host, bind_port)

    async def tcp_hold() -> None:
        try:
            while True:
                chunk = await client_tcp_reader.read(65536)
                if not chunk:
                    break
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass

    try:
        await asyncio.gather(tunnel_to_udp(transport), tcp_hold())
    finally:
        transport.close()
        try:
            tunnel_writer.close()
            await tunnel_writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            pass


async def handle_socks_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    *,
    pool: Optional[TunnelPool] = None,
) -> None:
    session_id = uuid.uuid4().hex[:8]
    peer = client_writer.get_extra_info("peername")
    _set_socket_options(client_writer)
    try:
        target_host, target_port, cmd = await socks5_handshake(
            client_reader, client_writer,
            proxy_user=getattr(args, "proxy_user", None),
            proxy_pass=getattr(args, "proxy_pass", None),
        )
        LOG.debug(
            "[sid=%s] request from %s cmd=0x%02x to %s:%s",
            session_id,
            peer,
            cmd,
            target_host,
            target_port,
        )

        if cmd == 0x03:
            await handle_socks_udp_relay(client_reader, client_writer, args, session_id, pool=pool)
            return

        tunnel_reader, tunnel_writer = await open_tunnel(
            target_host, target_port, args, session_id, pool=pool
        )
        await send_socks_reply(client_writer, 0x00)
        LOG.info(
            "[sid=%s] SOCKS CONNECT OK from %s to %s:%s (tunnel established)",
            session_id,
            peer,
            target_host,
            target_port,
        )

        await asyncio.gather(
            pipe(client_reader, tunnel_writer),
            pipe(tunnel_reader, client_writer),
        )
    except (
        SocksProtocolError,
        ConnectionError,
        OSError,
        asyncio.IncompleteReadError,
        TimeoutError,
        asyncio.TimeoutError,
    ) as exc:
        reply_code = map_socks_reply(exc)
        LOG.warning(
            "[sid=%s] SOCKS request failed from %s: %s (reply=0x%02x)",
            session_id,
            peer,
            exc,
            reply_code,
        )
        try:
            await send_socks_reply(client_writer, reply_code)
        except (ConnectionError, OSError, RuntimeError):
            pass
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            pass


def _check_http_basic_auth(
    header_block: bytes, proxy_user: str, proxy_pass: str
) -> bool:
    for line in header_block.split(b"\r\n"):
        if not line.lower().startswith(b"proxy-authorization:"):
            continue
        try:
            header_value = line.split(b":", 1)[1].strip()
            if not header_value.lower().startswith(b"basic "):
                continue
            b64val = header_value[6:].strip()
            decoded = base64.b64decode(b64val).decode("utf-8", errors="replace")
            user, _, password = decoded.partition(":")
            if user == proxy_user and password == proxy_pass:
                return True
        except Exception:
            pass
        break
    return False


_RESP_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b"Proxy-Authenticate: Basic realm=\"VPNProxy\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_RESP_400 = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"


async def handle_http_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    *,
    pool: Optional[TunnelPool] = None,
) -> None:
    session_id = uuid.uuid4().hex[:8]
    peer = client_writer.get_extra_info("peername")
    _set_socket_options(client_writer)
    proxy_user = getattr(args, "proxy_user", None)
    proxy_pass = getattr(args, "proxy_pass", None)
    try:
        header_block = await client_reader.readuntil(b"\r\n\r\n")
        if proxy_user is not None:
            if not _check_http_basic_auth(header_block, proxy_user, proxy_pass):
                client_writer.write(_RESP_407)
                await client_writer.drain()
                try:
                    header_block = await client_reader.readuntil(b"\r\n\r\n")
                except (ConnectionError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    return
                if not _check_http_basic_auth(header_block, proxy_user, proxy_pass):
                    client_writer.write(_RESP_407)
                    await client_writer.drain()
                    client_writer.close()
                    return
        target_host, target_port = parse_http_connect_target(header_block)
        LOG.debug(
            "[sid=%s] HTTP CONNECT from %s to %s:%s",
            session_id,
            peer,
            target_host,
            target_port,
        )
        tunnel_reader, tunnel_writer = await open_tunnel(
            target_host, target_port, args, session_id, pool=pool
        )
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        LOG.info(
            "[sid=%s] HTTP CONNECT OK from %s to %s:%s",
            session_id,
            peer,
            target_host,
            target_port,
        )
        await asyncio.gather(
            pipe(client_reader, tunnel_writer),
            pipe(tunnel_reader, client_writer),
        )
    except (
        HttpProxyError,
        ConnectionError,
        OSError,
        asyncio.IncompleteReadError,
        TimeoutError,
        asyncio.TimeoutError,
        asyncio.LimitOverrunError,
    ) as exc:
        LOG.warning("[sid=%s] HTTP proxy failed from %s: %s", session_id, peer, exc)
        try:
            if not client_writer.is_closing():
                client_writer.write(_RESP_400)
                await client_writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
        try:
            client_writer.close()
        except (ConnectionError, OSError, RuntimeError):
            pass


async def handle_tcp_line_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    *,
    pool: Optional[TunnelPool] = None,
) -> None:
    session_id = uuid.uuid4().hex[:8]
    peer = client_writer.get_extra_info("peername")
    _set_socket_options(client_writer)
    try:
        line = await client_reader.readline()
        if not line:
            return
        target_host, target_port = parse_tcp_line_target(line)
        LOG.debug(
            "[sid=%s] TCP line target from %s -> %s:%s",
            session_id,
            peer,
            target_host,
            target_port,
        )
        tunnel_reader, tunnel_writer = await open_tunnel(
            target_host, target_port, args, session_id, pool=pool
        )
        client_writer.write(b"OK\n")
        await client_writer.drain()
        LOG.info(
            "[sid=%s] TCP tunnel OK from %s to %s:%s",
            session_id,
            peer,
            target_host,
            target_port,
        )
        await asyncio.gather(
            pipe(client_reader, tunnel_writer),
            pipe(tunnel_reader, client_writer),
        )
    except (
        TcpLineTargetError,
        ConnectionError,
        OSError,
        asyncio.IncompleteReadError,
        TimeoutError,
        asyncio.TimeoutError,
    ) as exc:
        LOG.warning("[sid=%s] TCP line proxy failed from %s: %s", session_id, peer, exc)
        try:
            msg = f"ERR {exc}\n".encode("utf-8", errors="replace")
            client_writer.write(msg)
            await client_writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local SOCKS5/HTTP/TCP -> remote TLS tunnel proxy client"
    )
    parser.add_argument("--listen", default=os.getenv("VPN_PROXY_LOCAL_LISTEN", "127.0.0.1"))
    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.getenv("VPN_PROXY_LOCAL_PORT", "1080")),
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="optional local HTTP CONNECT port (env VPN_PROXY_HTTP_PORT)",
    )
    parser.add_argument(
        "--tcp-line-port",
        type=int,
        default=None,
        help="optional local TCP port: first line 'host:port' then raw stream (env VPN_PROXY_TCP_LINE_PORT)",
    )
    parser.add_argument("--server", default=os.getenv("VPN_PROXY_SERVER"), help="remote server host")
    parser.add_argument(
        "--server-port",
        type=int,
        default=int(os.getenv("VPN_PROXY_SERVER_PORT", "8443")),
    )
    parser.add_argument("--token", default=os.getenv("VPN_PROXY_TOKEN"), help="shared token")
    parser.add_argument("--ca-cert", default=os.getenv("VPN_PROXY_CA_CERT"))
    parser.add_argument("--sni", default=os.getenv("VPN_PROXY_SNI"))
    parser.add_argument(
        "--connect-retries",
        type=int,
        default=int(os.getenv("VPN_PROXY_CONNECT_RETRIES", "2")),
        help="number of retries when tunnel connection fails",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=float(os.getenv("VPN_PROXY_RETRY_DELAY", "0.8")),
        help="initial retry delay seconds (exponential backoff)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable certificate verification (not recommended)",
    )
    parser.add_argument(
        "--pool-size",
        type=int,
        default=int(os.getenv("VPN_PROXY_POOL_SIZE", "0")),
        help="pre-warmed TLS tunnel pool size (0=disabled, env VPN_PROXY_POOL_SIZE)",
    )
    parser.add_argument(
        "--pool-ttl",
        type=float,
        default=float(os.getenv("VPN_PROXY_POOL_TTL", "8.0")),
        help="seconds to keep warm connections in pool (env VPN_PROXY_POOL_TTL)",
    )
    parser.add_argument(
        "--proxy-user",
        default=os.getenv("VPN_PROXY_USER"),
        help="require proxy authentication: username (env VPN_PROXY_USER)",
    )
    parser.add_argument(
        "--proxy-pass",
        default=os.getenv("VPN_PROXY_PASS"),
        help="require proxy authentication: password (env VPN_PROXY_PASS)",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("VPN_PROXY_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


async def main_async(args: argparse.Namespace) -> None:
    if not args.server:
        raise SystemExit("missing --server or VPN_PROXY_SERVER")
    if not args.token:
        raise SystemExit("missing --token or VPN_PROXY_TOKEN")
    if (args.proxy_user is None) != (args.proxy_pass is None):
        raise SystemExit("--proxy-user and --proxy-pass must be specified together")

    pool: Optional[TunnelPool] = None
    if args.pool_size > 0:
        pool = TunnelPool(args, max_size=args.pool_size, ttl=args.pool_ttl)
        await pool.start()
        LOG.info("tunnel pool started (size=%d, ttl=%.1fs)", args.pool_size, args.pool_ttl)

    servers = []
    try:
        servers.append(
            await asyncio.start_server(
                lambda r, w: handle_socks_client(r, w, args, pool=pool),
                host=args.listen,
                port=args.listen_port,
            )
        )
        http_port = getattr(args, "http_port", None)
        tcp_line_port = getattr(args, "tcp_line_port", None)
        if http_port:
            servers.append(
                await asyncio.start_server(
                    lambda r, w: handle_http_client(r, w, args, pool=pool),
                    host=args.listen,
                    port=int(http_port),
                )
            )
        if tcp_line_port:
            servers.append(
                await asyncio.start_server(
                    lambda r, w: handle_tcp_line_client(r, w, args, pool=pool),
                    host=args.listen,
                    port=int(tcp_line_port),
                )
            )

        addrs = ", ".join(
            str(sock.getsockname()) for s in servers for sock in (s.sockets or [])
        )
        auth_info = f", auth={args.proxy_user}" if args.proxy_user else ""
        LOG.info("local proxy listening on %s%s", addrs, auth_info)
        try:
            await asyncio.gather(*(s.serve_forever() for s in servers))
        finally:
            for s in servers:
                s.close()
            await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
    finally:
        if pool:
            await pool.stop()


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.http_port is None and os.getenv("VPN_PROXY_HTTP_PORT"):
        hp = int(os.getenv("VPN_PROXY_HTTP_PORT", "0"))
        args.http_port = hp if hp > 0 else None
    if args.tcp_line_port is None and os.getenv("VPN_PROXY_TCP_LINE_PORT"):
        tp = int(os.getenv("VPN_PROXY_TCP_LINE_PORT", "0"))
        args.tcp_line_port = tp if tp > 0 else None
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
