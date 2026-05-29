#!/usr/bin/env python3
"""Performance benchmark for VPNProxy — cross-language (Python vs Go).

Measures:
  1. TLS handshake time: ECDSA P-256 vs RSA-4096
  2. TCP_NODELAY effect on small-packet RTT
  3. Socket buffer effect on throughput
  4. End-to-end proxy tunnel setup latency (Python + Go)
  5. Connection pool speedup (Python)
  6. Cross-language comparison summary

Usage:
  python scripts/benchmark.py
  python scripts/benchmark.py --iterations 50
  python scripts/benchmark.py --go-bin vpn-proxy-go/bin/vpn-proxy-server.exe
"""

import argparse
import asyncio
import json
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

RESULTS: dict = {}
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_SERVER_BIN = os.path.join(PROJECT_ROOT, "vpn-proxy-go", "bin", "vpn-proxy-server.exe")
RUST_SERVER_BIN = os.path.join(PROJECT_ROOT, "vpn-proxy-rust", "target", "release", "vpn-proxy-server.exe")


def log(msg: str) -> None:
    """Print progress with immediate flush so user sees activity."""
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def generate_cert(cert_dir: str, algo: str) -> None:
    """Generate a self-signed TLS cert for benchmarking (ECDSA P-256 or RSA-4096)."""
    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")
    has_openssl = shutil.which("openssl") is not None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID
        import datetime
        _cryptography_available = True
    except ImportError:
        _cryptography_available = False

    if has_openssl:
        if algo == "ecdsa":
            subprocess.run(
                ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", key_path],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["openssl", "req", "-x509", "-new", "-key", key_path, "-out", crt_path,
                 "-sha256", "-days", "1", "-nodes", "-subj", "/CN=bench-server",
                 "-addext", "subjectAltName=DNS:bench-server,IP:127.0.0.1"],
                check=True, capture_output=True,
            )
        else:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", key_path,
                 "-out", crt_path, "-sha256", "-days", "1", "-nodes",
                 "-subj", "/CN=bench-server",
                 "-addext", "subjectAltName=DNS:bench-server,IP:127.0.0.1"],
                check=True, capture_output=True,
            )
    elif _cryptography_available:
        import ipaddress as ipmod
        if algo == "ecdsa":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bench-server")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("bench-server"),
                 x509.IPAddress(ipmod.IPv4Address("127.0.0.1"))]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    else:
        raise RuntimeError("Neither openssl nor cryptography library available")


def _make_py_proxy_handler(token: str, connect_timeout: float = 5.0,
                           bootstrap_timeout: float = 30.0):
    """Factory: returns a real `async def` callback for asyncio.start_server.

    Must NOT use functools.partial or lambdas on Windows ProactorEventLoop
    because they are not recognized as coroutine functions.
    """
    import server as _svr

    async def _handler(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter):
        await _svr.handle_client(
            reader, writer,
            allowed_tokens={token},
            allow_networks=[],
            connect_timeout=connect_timeout,
            bootstrap_timeout=bootstrap_timeout,
        )
    return _handler


async def _echo_handler(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Go server subprocess management ──────────────────────────────────────

async def start_go_server(cert_dir: str, port: int, token: str,
                          go_bin: str = GO_SERVER_BIN) -> asyncio.subprocess.Process:
    """Start Go server as subprocess, return process handle."""
    log(f"starting Go server on 127.0.0.1:{port} ...")
    proc = await asyncio.create_subprocess_exec(
        go_bin,
        f"--port={port}",
        f"--cert={os.path.join(cert_dir, 'server.crt')}",
        f"--key={os.path.join(cert_dir, 'server.key')}",
        f"--token={token}",
        "--listen=127.0.0.1",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(0.8)  # wait for TLS listener
    log("Go server started")
    return proc


async def stop_go_server(proc: asyncio.subprocess.Process) -> None:
    """Gracefully stop the Go server subprocess."""
    log("stopping Go server ...")
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        log("Go server didn't stop in 5s, killing ...")
        proc.kill()
        await proc.wait()
    log("Go server stopped")


# ── Rust server subprocess management ─────────────────────────────────────

async def start_rust_server(cert_dir: str, port: int, token: str,
                            rust_bin: str = RUST_SERVER_BIN) -> asyncio.subprocess.Process:
    """Start Rust server as subprocess, return process handle."""
    log(f"starting Rust server on 127.0.0.1:{port} ...")
    proc = await asyncio.create_subprocess_exec(
        rust_bin,
        "--listen=127.0.0.1",
        f"--port={port}",
        f"--cert={os.path.join(cert_dir, 'server.crt')}",
        f"--key={os.path.join(cert_dir, 'server.key')}",
        f"--token={token}",
        "--rate-limit=1000",
        "--rate-burst=100",
        "--max-conns=0",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(0.8)  # wait for TLS listener
    log("Rust server started")
    return proc


async def stop_rust_server(proc: asyncio.subprocess.Process) -> None:
    """Gracefully stop the Rust server subprocess."""
    log("stopping Rust server ...")
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        log("Rust server didn't stop in 5s, killing ...")
        proc.kill()
        await proc.wait()
    log("Rust server stopped")


def find_free_port() -> int:
    """Return a free TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── Test 1: TLS handshake ─────────────────────────────────────────────────

async def bench_tls_handshake(cert_dir: str, algo: str, iterations: int) -> list[float]:
    """Measure TLS handshake time for a given cert type."""
    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE

    async def _handler(reader, writer):
        while True:
            d = await reader.read(65536)
            if not d:
                break
            writer.write(d)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(_handler, host="127.0.0.1", port=0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]

    log(f"TLS handshake benchmark ({algo}), {iterations} iters on port {port} ...")
    times = []
    for i in range(iterations):
        t0 = time.perf_counter()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ctx, server_hostname="bench-server"
        )
        t1 = time.perf_counter()
        writer.write(b"ping")
        await writer.drain()
        await reader.read(4)
        writer.close()
        await writer.wait_closed()
        times.append((t1 - t0) * 1000)
        if (i + 1) % 10 == 0:
            log(f"  TLS {algo}: {i+1}/{iterations} done (mean={statistics.mean(times):.2f}ms)")

    server.close()
    await server.wait_closed()
    return times


# ── Test 2: TCP_NODELAY ───────────────────────────────────────────────────

async def bench_tcp_nodelay(iterations: int) -> dict:
    """Compare small-packet RTT with and without TCP_NODELAY."""
    results: dict = {"nodelay_on": [], "nodelay_off": []}

    log(f"TCP_NODELAY RTT benchmark, {iterations} iters ...")

    for mode, nodelay in [("nodelay_on", True), ("nodelay_off", False)]:
        log(f"  mode={mode} ...")

        def _make_handler(nl: bool):
            async def _h(reader, writer):
                if nl:
                    sock = writer.get_extra_info("socket")
                    if sock:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while True:
                    d = await reader.read(65536)
                    if not d:
                        break
                    writer.write(d)
                    await writer.drain()
                writer.close()
            return _h

        server = await asyncio.start_server(
            _make_handler(nodelay), host="127.0.0.1", port=0
        )
        port = server.sockets[0].getsockname()[1]

        for i in range(iterations):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            if nodelay:
                sock = writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            ping = b"x" * 1
            t0 = time.perf_counter()
            for _ in range(10):
                writer.write(ping)
                await writer.drain()
                await reader.readexactly(len(ping))
            t1 = time.perf_counter()
            rtt = (t1 - t0) * 1000 / 10
            results[mode].append(rtt)

            writer.close()
            await writer.wait_closed()

        server.close()
        await server.wait_closed()
        log(f"  {mode} done: mean={statistics.mean(results[mode]):.3f}ms")

    return results


# ── Test 3: Socket buffer throughput ──────────────────────────────────────

async def bench_throughput(size_mb: int) -> dict:
    """Measure throughput (MB/s) with default vs large socket buffers."""
    data = b"x" * (64 * 1024)
    total_bytes = size_mb * 1024 * 1024
    results: dict = {}

    log(f"Socket buffer throughput benchmark ({size_mb}MB) ...")

    for mode, buf_size in [("default_buf", 0), ("large_buf", 256 * 1024)]:
        log(f"  mode={mode} (buf={buf_size}) ...")

        def _make_handler(bs: int):
            async def _h(reader, writer):
                # Set TCP_NODELAY + socket buffer on server side
                sock = writer.get_extra_info("socket")
                if sock:
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except OSError:
                        pass
                    if bs > 0:
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bs)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bs)
                        except OSError:
                            pass
                while True:
                    try:
                        d = await asyncio.wait_for(reader.read(65536), timeout=30)
                    except asyncio.TimeoutError:
                        break
                    if not d:
                        break
                    writer.write(d)
                    try:
                        await asyncio.wait_for(writer.drain(), timeout=30)
                    except asyncio.TimeoutError:
                        break
                try:
                    writer.close()
                except Exception:
                    pass
            return _h

        server = await asyncio.start_server(
            _make_handler(buf_size), host="127.0.0.1", port=0
        )
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Set TCP_NODELAY on client side + socket buffer
        sock = writer.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            if buf_size > 0:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buf_size)
                except OSError:
                    pass

        try:
            sent = 0
            t0 = time.perf_counter()
            while sent < total_bytes:
                chunk = data if (sent + len(data)) <= total_bytes else data[: total_bytes - sent]
                writer.write(chunk)
                await asyncio.wait_for(writer.drain(), timeout=30)
                sent += len(chunk)

            remaining = total_bytes
            while remaining > 0:
                r = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=30)
                if not r:
                    break
                remaining -= len(r)

            t1 = time.perf_counter()
            elapsed = t1 - t0
            throughput_mb = total_bytes / (1024 * 1024) / elapsed
            results[mode] = {
                "throughput_mbps": round(throughput_mb, 2),
                "elapsed_s": round(elapsed, 3),
            }
            log(f"  {mode}: {throughput_mb:.1f} MB/s ({elapsed:.3f}s)")
        except (Exception, asyncio.TimeoutError) as e:
            log(f"  {mode} FAILED: {e}")
            results[mode] = {"throughput_mbps": 0, "elapsed_s": 0}

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        server.close()
        await server.wait_closed()

    return results


# ── Test 4: Python proxy tunnel setup ─────────────────────────────────────

async def bench_py_proxy(cert_dir: str, iterations: int) -> dict:
    """End-to-end proxy tunnel setup using Python server + Python client."""
    sys.path.insert(0, PROJECT_ROOT)
    import client as cli

    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")

    # Generate cert if not already present
    if not os.path.isfile(crt_path):
        generate_cert(cert_dir, "ecdsa")

    results: dict = {"tunnel_setup_ms": []}

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    token = "bench-token-" + uuid.uuid4().hex[:8]

    proxy_server = await asyncio.start_server(
        _make_py_proxy_handler(token, 5.0, 30.0),
        host="127.0.0.1", port=0, ssl=ssl_ctx,
    )
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    log(f"Python proxy server on 127.0.0.1:{proxy_port}")

    target_server = await asyncio.start_server(
        _echo_handler, host="127.0.0.1", port=0
    )
    target_port = target_server.sockets[0].getsockname()[1]
    log(f"Echo target on 127.0.0.1:{target_port}")

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=proxy_port,
        token=token,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
        pool_size=0,
        pool_ttl=8.0,
    )

    log(f"Python proxy benchmark: {iterations} iterations ...")
    # Warmup: first connection (cold TLS handshake, excluded from results)
    try:
        wr, ww = await cli.open_tunnel(
            "127.0.0.1", target_port, args, "bench-py-warmup"
        )
        ww.close()
        await ww.wait_closed()
    except Exception:
        pass

    for i in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", target_port, args, "bench-py"
            )
        except Exception as e:
            log(f"  iter {i+1} FAILED: {e}")
            continue
        t1 = time.perf_counter()
        ms = (t1 - t0) * 1000
        results["tunnel_setup_ms"].append(ms)

        tunnel_writer.close()
        await tunnel_writer.wait_closed()
        if (i + 1) % 5 == 0:
            log(f"  Python: {i+1}/{iterations} done (mean={statistics.mean(results['tunnel_setup_ms']):.1f}ms)")

    proxy_server.close()
    target_server.close()
    await proxy_server.wait_closed()
    await target_server.wait_closed()
    log(f"Python proxy benchmark done, {len(results['tunnel_setup_ms'])}/{iterations} succeeded")
    return results


# ── Test 5: Go proxy tunnel setup ─────────────────────────────────────────

async def bench_go_proxy(cert_dir: str, iterations: int,
                         go_bin: str = GO_SERVER_BIN) -> dict:
    """End-to-end proxy tunnel setup using Go server + Python client."""
    sys.path.insert(0, PROJECT_ROOT)
    import client as cli

    token = "bench-token-" + uuid.uuid4().hex[:8]
    go_port = find_free_port()

    go_proc = await start_go_server(cert_dir, go_port, token, go_bin)

    results: dict = {"tunnel_setup_ms": []}

    target_server = await asyncio.start_server(
        _echo_handler, host="127.0.0.1", port=0
    )
    target_port = target_server.sockets[0].getsockname()[1]
    log(f"Echo target on 127.0.0.1:{target_port}")

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=go_port,
        token=token,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
        pool_size=0,
        pool_ttl=8.0,
    )

    log(f"Go proxy benchmark: {iterations} iterations ...")
    # Warmup: first connection (cold TLS handshake, excluded from results)
    try:
        wr, ww = await cli.open_tunnel(
            "127.0.0.1", target_port, args, "bench-go-warmup"
        )
        ww.close()
        await ww.wait_closed()
    except Exception:
        pass

    for i in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", target_port, args, "bench-go"
            )
        except Exception as e:
            log(f"  iter {i+1} FAILED: {e}")
            continue
        t1 = time.perf_counter()
        ms = (t1 - t0) * 1000
        results["tunnel_setup_ms"].append(ms)

        tunnel_writer.close()
        await tunnel_writer.wait_closed()
        if (i + 1) % 5 == 0:
            log(f"  Go: {i+1}/{iterations} done (mean={statistics.mean(results['tunnel_setup_ms']):.1f}ms)")

    target_server.close()
    await target_server.wait_closed()
    await stop_go_server(go_proc)
    log(f"Go proxy benchmark done, {len(results['tunnel_setup_ms'])}/{iterations} succeeded")
    return results


# ── Test 4c: Rust proxy tunnel setup ───────────────────────────────────────

async def bench_rust_proxy(cert_dir: str, iterations: int,
                           rust_bin: str = RUST_SERVER_BIN) -> dict:
    """End-to-end proxy tunnel setup using Rust server + Python client."""
    sys.path.insert(0, PROJECT_ROOT)
    import client as cli

    token = "bench-token-" + uuid.uuid4().hex[:8]
    rust_port = find_free_port()

    rust_proc = await start_rust_server(cert_dir, rust_port, token, rust_bin)

    results: dict = {"tunnel_setup_ms": []}

    target_server = await asyncio.start_server(
        _echo_handler, host="127.0.0.1", port=0
    )
    target_port = target_server.sockets[0].getsockname()[1]
    log(f"Echo target on 127.0.0.1:{target_port}")

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=rust_port,
        token=token,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
        pool_size=0,
        pool_ttl=8.0,
    )

    log(f"Rust proxy benchmark: {iterations} iterations ...")
    # Warmup: first connection (cold TLS handshake, excluded from results)
    try:
        wr, ww = await cli.open_tunnel(
            "127.0.0.1", target_port, args, "bench-rust-warmup"
        )
        ww.close()
        await ww.wait_closed()
    except Exception:
        pass

    for i in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", target_port, args, "bench-rust"
            )
        except Exception as e:
            log(f"  iter {i+1} FAILED: {e}")
            continue
        t1 = time.perf_counter()
        ms = (t1 - t0) * 1000
        results["tunnel_setup_ms"].append(ms)

        tunnel_writer.close()
        await tunnel_writer.wait_closed()
        if (i + 1) % 5 == 0:
            log(f"  Rust: {i+1}/{iterations} done (mean={statistics.mean(results['tunnel_setup_ms']):.1f}ms)")

    target_server.close()
    await target_server.wait_closed()
    await stop_rust_server(rust_proc)
    log(f"Rust proxy benchmark done, {len(results['tunnel_setup_ms'])}/{iterations} succeeded")
    return results


# ── Test 6: Python connection pool ────────────────────────────────────────

async def bench_py_pool(cert_dir: str, iterations: int) -> dict:
    """Measure tunnel setup latency with Python connection pool."""
    sys.path.insert(0, PROJECT_ROOT)
    import client as cli

    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")

    # Generate cert if not already present
    if not os.path.isfile(crt_path):
        generate_cert(cert_dir, "ecdsa")

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    token = "bench-token-" + uuid.uuid4().hex[:8]

    proxy_server = await asyncio.start_server(
        _make_py_proxy_handler(token, 5.0, 30.0),
        host="127.0.0.1", port=0, ssl=ssl_ctx,
    )
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    log(f"Python pool proxy on 127.0.0.1:{proxy_port}")

    # Start a target echo server so the proxy has a backend to connect to
    target_server = await asyncio.start_server(
        _echo_handler, host="127.0.0.1", port=0
    )
    target_port = target_server.sockets[0].getsockname()[1]
    log(f"Pool echo target on 127.0.0.1:{target_port}")

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=proxy_port,
        token=token,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
        pool_size=2,
        pool_ttl=8.0,
    )

    pool = cli.TunnelPool(args, max_size=2, ttl=8.0)
    await pool.start()
    await asyncio.sleep(1.0)
    log("Python connection pool warmed up (size=2)")

    results: dict = {"pool_setup_ms": []}

    log(f"Python pool benchmark: {iterations} iterations ...")
    for i in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", target_port, args, "bench-pool", pool=pool
            )
        except Exception as e:
            log(f"  iter {i+1} FAILED: {e}")
            continue
        t1 = time.perf_counter()
        ms = (t1 - t0) * 1000
        results["pool_setup_ms"].append(ms)

        try:
            tunnel_writer.close()
            await tunnel_writer.wait_closed()
        except Exception:
            pass
        if (i + 1) % 5 == 0:
            log(f"  Pool: {i+1}/{iterations} done (mean={statistics.mean(results['pool_setup_ms']):.1f}ms)")

    await pool.stop()
    proxy_server.close()
    await proxy_server.wait_closed()
    target_server.close()
    await target_server.wait_closed()
    log(f"Python pool benchmark done, {len(results['pool_setup_ms'])}/{iterations} succeeded")
    return results


# ── Utility ───────────────────────────────────────────────────────────────

def fmt_stats(times: list[float]) -> str:
    if not times:
        return "N/A"
    sorted_t = sorted(times)
    return (
        f"mean={statistics.mean(times):.2f}ms "
        f"median={statistics.median(times):.2f}ms "
        f"p95={sorted_t[int(len(sorted_t)*0.95)]:.2f}ms "
        f"min={min(times):.2f}ms"
    )


def fmt_throughput(mbps: float) -> str:
    return f"{mbps:.1f} MB/s"


# ── Main ─────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="VPNProxy cross-language performance benchmark")
    parser.add_argument("--iterations", type=int, default=20, help="iterations per test")
    parser.add_argument("--size-mb", type=int, default=4, help="MB for throughput test")
    parser.add_argument("--skip-pool", action="store_true", help="skip pool benchmark")
    parser.add_argument("--go-bin", type=str, default=GO_SERVER_BIN,
                        help="path to Go server binary")
    parser.add_argument("--skip-go", action="store_true", help="skip Go benchmarks")
    parser.add_argument("--rust-bin", type=str, default=RUST_SERVER_BIN,
                        help="path to Rust server binary")
    parser.add_argument("--skip-rust", action="store_true", help="skip Rust benchmarks")
    parser.add_argument("--skip-throughput", action="store_true",
                        help="skip socket throughput test (flaky on Windows)")
    args = parser.parse_args()

    print("=" * 72, flush=True)
    print("  VPNProxy Performance Benchmark — Cross-Language Comparison", flush=True)
    print("=" * 72, flush=True)

    iters = args.iterations
    size_mb = args.size_mb

    # ── Test 1: TLS Handshake ─────────────────────────────────────────────
    log("=" * 60)
    log("TEST [1/5] TLS Handshake")
    log("=" * 60)
    with tempfile.TemporaryDirectory() as cert_dir:
        log("generating ECDSA P-256 cert ...")
        generate_cert(cert_dir, "ecdsa")
        tls_ecdsa = await bench_tls_handshake(cert_dir, "ecdsa", iters)

        log("generating RSA-4096 cert ...")
        generate_cert(cert_dir, "rsa")
        tls_rsa = await bench_tls_handshake(cert_dir, "rsa", iters)

        print(f"\n  ── TLS Handshake ({iters} iterations) ──", flush=True)
        print(f"    ECDSA P-256:  {fmt_stats(tls_ecdsa)}", flush=True)
        print(f"    RSA-4096:     {fmt_stats(tls_rsa)}", flush=True)
        if tls_ecdsa and tls_rsa:
            ratio_r = statistics.mean(tls_rsa) / max(0.001, statistics.mean(tls_ecdsa))
            print(f"    ECDSA speedup: {ratio_r:.2f}x faster", flush=True)
            RESULTS["tls_ecdsa"] = statistics.mean(tls_ecdsa)
            RESULTS["tls_rsa"] = statistics.mean(tls_rsa)

    # ── Test 2: TCP_NODELAY ───────────────────────────────────────────────
    log("=" * 60)
    log("TEST [2/5] TCP_NODELAY small-packet RTT")
    log("=" * 60)
    nodelay = await bench_tcp_nodelay(iters)
    print(f"\n  ── TCP_NODELAY RTT (10 ping-pongs, {iters} iterations) ──", flush=True)
    print(f"    NODELAY ON:   {fmt_stats(nodelay['nodelay_on'])}", flush=True)
    print(f"    NODELAY OFF:  {fmt_stats(nodelay['nodelay_off'])}", flush=True)
    if nodelay["nodelay_on"] and nodelay["nodelay_off"]:
        ratio = statistics.mean(nodelay["nodelay_off"]) / max(0.001, statistics.mean(nodelay["nodelay_on"]))
        print(f"    NODELAY improvement: {ratio:.2f}x", flush=True)
        RESULTS["nodelay_ratio"] = ratio

    # ── Test 3: Socket buffer throughput (flaky on Windows, skip by default)
    if not args.skip_throughput:
        log("=" * 60)
        log(f"TEST [3/5] Socket buffer throughput ({size_mb}MB)")
        log("=" * 60)
        try:
            throughput = await bench_throughput(size_mb)
            default_tp = throughput["default_buf"]["throughput_mbps"]
            large_tp = throughput["large_buf"]["throughput_mbps"]
            title = f"\n  ── Socket Buffer Throughput ({size_mb}MB transfer) ──"
            print(title, flush=True)
            def_buf = throughput['default_buf']
            print(f"    Default buffers:  {fmt_throughput(default_tp)}"
                  f" ({def_buf['elapsed_s']:.3f}s)", flush=True)
            lrg_buf = throughput['large_buf']
            print(f"    Large buffers:    {fmt_throughput(large_tp)}"
                  f" ({lrg_buf['elapsed_s']:.3f}s)", flush=True)
            if default_tp > 0:
                print(f"    Large buffer speedup: {large_tp / default_tp:.2f}x", flush=True)
            RESULTS["throughput_default"] = default_tp
            RESULTS["throughput_large"] = large_tp
        except Exception as e:
            log(f"Throughput test SKIPPED (Windows drain issue: {e})")
    else:
        log("TEST [3/5] Socket buffer throughput — SKIPPED")

    # ── Tests 4-6: cross-language proxy comparison ───────────────────────
    py_setup = None
    with tempfile.TemporaryDirectory() as cert_dir:
        log("generating ECDSA cert ...")
        generate_cert(cert_dir, "ecdsa")
        cert_exists = os.path.isfile(os.path.join(cert_dir, "server.crt"))
        log(f"cert {'OK' if cert_exists else 'MISSING'} in {cert_dir}")

        # 4. Python proxy
        log("=" * 60)
        log("TEST [4/5] Python Proxy — tunnel setup")
        log("=" * 60)
        py_proxy = await bench_py_proxy(cert_dir, iters)
        py_setup = py_proxy["tunnel_setup_ms"]
        print(f"\n  ── Python Server + Python Client ──", flush=True)
        print(f"    Tunnel setup: {fmt_stats(py_setup)}", flush=True)
        RESULTS["py_tunnel_setup"] = statistics.mean(py_setup) if py_setup else None

        # 5. Go proxy
        log("=" * 60)
        go_setup = None
        if not args.skip_go and os.path.isfile(args.go_bin):
            log("TEST [4b/5] Go Proxy — tunnel setup")
            log("=" * 60)
            go_proxy = await bench_go_proxy(cert_dir, iters, args.go_bin)
            go_setup = go_proxy["tunnel_setup_ms"]
            print(f"\n  ── Go Server + Python Client ──", flush=True)
            print(f"    Tunnel setup: {fmt_stats(go_setup)}", flush=True)
            RESULTS["go_tunnel_setup"] = statistics.mean(go_setup) if go_setup else None
        else:
            bin_msg = "binary not found" if not os.path.isfile(args.go_bin) else "skipped"
            log(f"TEST [4b/5] Go Proxy — SKIPPED ({bin_msg})")

        # 4c. Rust proxy
        rust_setup = None
        if not args.skip_rust and os.path.isfile(args.rust_bin):
            log("=" * 60)
            log("TEST [4c/5] Rust Proxy — tunnel setup")
            log("=" * 60)
            rust_proxy = await bench_rust_proxy(cert_dir, iters, args.rust_bin)
            rust_setup = rust_proxy["tunnel_setup_ms"]
            print(f"\n  ── Rust Server + Python Client ──", flush=True)
            print(f"    Tunnel setup: {fmt_stats(rust_setup)}", flush=True)
            RESULTS["rust_tunnel_setup"] = statistics.mean(rust_setup) if rust_setup else None
        else:
            bin_msg = "binary not found" if not os.path.isfile(args.rust_bin) else "skipped"
            log(f"TEST [4c/5] Rust Proxy — SKIPPED ({bin_msg})")

    # ── Pool test in separate temp dir ───────────────────────────────────
    if not args.skip_pool:
        log("=" * 60)
        log("BONUS: Python Connection Pool")
        log("=" * 60)
        with tempfile.TemporaryDirectory() as cert_dir:
            generate_cert(cert_dir, "ecdsa")
            log(f"pool cert dir: {cert_dir}")
            py_pool = await bench_py_pool(cert_dir, iters)
            pool_setup = py_pool["pool_setup_ms"]
            print(f"\n  ── Python Pool (size=2, ttl=8s) ──", flush=True)
            print(f"    Pool hit setup: {fmt_stats(pool_setup)}", flush=True)
            if py_setup and pool_setup:
                no_pool = statistics.mean(py_setup)
                with_pool = statistics.mean(pool_setup)
                if with_pool > 0:
                    pool_ratio = no_pool / with_pool
                    print(f"    Pool speedup vs no-pool: {pool_ratio:.2f}x", flush=True)
                    RESULTS["pool_speedup"] = pool_ratio
            RESULTS["py_pool_setup"] = statistics.mean(pool_setup) if pool_setup else None

    # ── Summary table ─────────────────────────────────────────────────────
    print("\n" + "=" * 72, flush=True)
    print("  SUMMARY — Cross-Language Performance Comparison", flush=True)
    print("=" * 72, flush=True)

    headers = ["Metric", "Python", "Go", "Rust", "Winner"]
    col_w = [30, 18, 18, 18, 10]

    def print_row(cols):
        parts = "".join(c.ljust(w) for c, w in zip(cols, col_w))
        print(f"  {parts}", flush=True)

    print()
    print_row(headers)
    print("  " + "-" * (sum(col_w)), flush=True)

    py_tunnel = RESULTS.get("py_tunnel_setup")
    go_tunnel = RESULTS.get("go_tunnel_setup")
    rust_tunnel = RESULTS.get("rust_tunnel_setup")
    py_tun_str = f"{py_tunnel:.1f}ms" if py_tunnel else "N/A"
    go_tun_str = f"{go_tunnel:.1f}ms" if go_tunnel else "N/A"
    rust_tun_str = f"{rust_tunnel:.1f}ms" if rust_tunnel else "N/A"
    candidates = {}
    if py_tunnel:
        candidates["Python"] = py_tunnel
    if go_tunnel:
        candidates["Go"] = go_tunnel
    if rust_tunnel:
        candidates["Rust"] = rust_tunnel
    winner = min(candidates, key=candidates.get) if candidates else "—"
    print_row(["Tunnel Setup (mean)", py_tun_str, go_tun_str, rust_tun_str, winner])

    py_pool_v = RESULTS.get("py_pool_setup")
    pool_spd = RESULTS.get("pool_speedup")
    py_pool_str = f"{py_pool_v:.1f}ms" if py_pool_v else "N/A"
    pool_str = f"{pool_spd:.1f}x" if pool_spd else "N/A"
    print_row(["Pool Setup (mean)", py_pool_str, "N/A", "N/A", "—"])

    print_row(["Throughput (large buf)",
               f"{RESULTS.get('throughput_large', 0):.1f} MB/s",
               "N/A", "N/A", "—"])

    print("  " + "-" * (sum(col_w)), flush=True)

    if py_tunnel and go_tunnel and rust_tunnel and py_tunnel > 0:
        # Lower is better. ratio = py / go: >1 means Go/Rust wins (lower latency)
        go_vs_py = py_tunnel / go_tunnel
        rust_vs_py = py_tunnel / rust_tunnel
        rust_vs_go = go_tunnel / rust_tunnel
        print(f"\n  >> Go server is {go_vs_py:.2f}x faster than Python in tunnel setup", flush=True)
        print(f"  >> Rust server is {rust_vs_py:.2f}x faster than Python in tunnel setup", flush=True)
        print(f"  >> Rust server is {rust_vs_go:.2f}x faster than Go in tunnel setup", flush=True)
        RESULTS["go_vs_py_speedup"] = go_vs_py
        RESULTS["rust_vs_py_speedup"] = rust_vs_py
        RESULTS["rust_vs_go_speedup"] = rust_vs_go
    elif py_tunnel and go_tunnel and py_tunnel > 0:
        # Lower is better. ratio = py / go: >1 means Go wins (lower latency)
        ratio = py_tunnel / go_tunnel
        if ratio > 1:
            print(f"\n  >> Go server is {ratio:.2f}x faster than Python in tunnel setup", flush=True)
        else:
            print(f"\n  >> Python server is {1/ratio:.2f}x faster than Go in tunnel setup", flush=True)
        RESULTS["go_vs_py_speedup"] = ratio
    elif py_tunnel and rust_tunnel and py_tunnel > 0:
        # Lower is better. ratio = py / go: >1 means Rust wins (lower latency)
        ratio = py_tunnel / rust_tunnel
        if ratio > 1:
            print(f"\n  >> Rust server is {ratio:.2f}x faster than Python in tunnel setup", flush=True)
        else:
            print(f"\n  >> Python server is {1/ratio:.2f}x faster than Rust in tunnel setup", flush=True)
        RESULTS["rust_vs_py_speedup"] = ratio
    else:
        not_avail = []
        if not go_tunnel:
            not_avail.append("Go")
        if not rust_tunnel:
            not_avail.append("Rust")
        avail = ' and '.join(not_avail)
        plural = len(not_avail) > 1
        print(f"\n  >> {avail} {'binaries' if plural else 'binary'} not available — comparison limited", flush=True)

    print("\n" + "=" * 72, flush=True)
    print("  Benchmark complete.", flush=True)
    print("=" * 72, flush=True)

    # Save results to JSON
    results_path = os.path.join(PROJECT_ROOT, "logs", "benchmark_results.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    try:
        with open(results_path, "w") as f:
            json.dump(RESULTS, f, indent=2)
        log(f"Results saved to: {results_path}")
    except Exception as e:
        log(f"Results not saved: {e}")


if __name__ == "__main__":
    asyncio.run(main())
