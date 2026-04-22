#!/usr/bin/env python3
"""Performance benchmark for VPNProxy optimizations.

Measures:
  1. TLS handshake time: ECDSA P-256 vs RSA-4096
  2. TCP_NODELAY effect on small-packet RTT
  3. Socket buffer effect on throughput
  4. Connection pool effect on tunnel setup latency
  5. End-to-end proxy throughput and latency

Usage:
  python scripts/benchmark.py
  python scripts/benchmark.py --iterations 50
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


def generate_cert(cert_dir: str, algo: str) -> None:
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
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID
        import datetime
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
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("bench-server"), x509.IPAddress(ipmod.IPv4Address("127.0.0.1"))]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    else:
        raise RuntimeError("Neither openssl nor cryptography library available for certificate generation")


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

    async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(
        echo_handler, host="127.0.0.1", port=0, ssl=ssl_ctx
    )
    port = server.sockets[0].getsockname()[1]

    times = []
    for _ in range(iterations):
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

    server.close()
    await server.wait_closed()
    return times


async def bench_tcp_nodelay(iterations: int) -> dict:
    """Compare small-packet RTT with and without TCP_NODELAY."""
    results: dict = {"nodelay_on": [], "nodelay_off": []}

    async def echo_handler_factory(nodelay: bool):
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            if nodelay:
                sock = writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
            writer.close()
        return handler

    for mode, nodelay in [("nodelay_on", True), ("nodelay_off", False)]:
        server = await asyncio.start_server(
            echo_handler_factory(nodelay), host="127.0.0.1", port=0
        )
        port = server.sockets[0].getsockname()[1]

        for _ in range(iterations):
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

    return results


async def bench_throughput(size_mb: int) -> dict:
    """Measure throughput (MB/s) with default vs large socket buffers."""
    data = b"x" * (64 * 1024)
    total_bytes = size_mb * 1024 * 1024
    results: dict = {}

    async def echo_handler_factory(buf_size: int):
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            if buf_size > 0:
                sock = writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buf_size)
            while True:
                d = await reader.read(65536)
                if not d:
                    break
                writer.write(d)
                await writer.drain()
            writer.close()
        return handler

    for mode, buf_size in [("default_buf", 0), ("large_buf", 256 * 1024)]:
        server = await asyncio.start_server(
            echo_handler_factory(buf_size), host="127.0.0.1", port=0
        )
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        if buf_size > 0:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buf_size)

        sent = 0
        t0 = time.perf_counter()
        while sent < total_bytes:
            chunk = data if (sent + len(data)) <= total_bytes else data[: total_bytes - sent]
            writer.write(chunk)
            await writer.drain()
            sent += len(chunk)

        remaining = total_bytes
        while remaining > 0:
            r = await reader.read(min(65536, remaining))
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

        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

    return results


async def bench_full_proxy(cert_dir: str, iterations: int) -> dict:
    """End-to-end proxy latency and throughput using server.py and client.py."""
    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import server as svr
    import client as cli

    results: dict = {"tunnel_setup_ms": [], "echo_rtt_ms": []}

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    token = "bench-token-" + uuid.uuid4().hex[:8]

    proxy_server = await asyncio.start_server(
        lambda r, w: svr.handle_client(r, w, {token}, [], 5.0, bootstrap_timeout=30.0),
        host="127.0.0.1", port=0, ssl=ssl_ctx,
    )
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    target_server = await asyncio.start_server(
        lambda r, w: _echo_handler(r, w), host="127.0.0.1", port=0
    )
    target_port = target_server.sockets[0].getsockname()[1]

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

    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", target_port, args, "bench"
            )
        except Exception:
            continue
        t1 = time.perf_counter()
        results["tunnel_setup_ms"].append((t1 - t0) * 1000)

        payload = b"hello-benchmark"
        tunnel_writer.write(payload)
        await tunnel_writer.drain()
        resp = await asyncio.wait_for(
            tunnel_reader.readexactly(len(payload)), timeout=5.0
        )

        tunnel_writer.close()
        await tunnel_writer.wait_closed()

    proxy_server.close()
    target_server.close()
    await proxy_server.wait_closed()
    await target_server.wait_closed()
    return results


async def bench_proxy_with_pool(cert_dir: str, iterations: int) -> dict:
    """Measure tunnel setup latency with connection pool enabled."""
    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import server as svr
    import client as cli

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    token = "bench-token-" + uuid.uuid4().hex[:8]

    proxy_server = await asyncio.start_server(
        lambda r, w: svr.handle_client(r, w, {token}, [], 5.0, bootstrap_timeout=30.0),
        host="127.0.0.1", port=0, ssl=ssl_ctx,
    )
    proxy_port = proxy_server.sockets[0].getsockname()[1]

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

    results: dict = {"pool_setup_ms": []}

    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            tunnel_reader, tunnel_writer = await cli.open_tunnel(
                "127.0.0.1", 80, args, "bench-pool", pool=pool
            )
        except Exception:
            continue
        t1 = time.perf_counter()
        results["pool_setup_ms"].append((t1 - t0) * 1000)

        try:
            tunnel_writer.close()
            await tunnel_writer.wait_closed()
        except Exception:
            pass

    await pool.stop()
    proxy_server.close()
    await proxy_server.wait_closed()
    return results


async def _echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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


def fmt_stats(times: list[float]) -> str:
    if not times:
        return "N/A"
    return (
        f"mean={statistics.mean(times):.2f}ms "
        f"median={statistics.median(times):.2f}ms "
        f"p95={sorted(times)[int(len(times)*0.95)]:.2f}ms "
        f"min={min(times):.2f}ms"
    )


async def main():
    parser = argparse.ArgumentParser(description="VPNProxy performance benchmark")
    parser.add_argument("--iterations", type=int, default=30, help="iterations per test")
    parser.add_argument("--size-mb", type=int, default=4, help="MB for throughput test")
    parser.add_argument("--skip-pool", action="store_true", help="skip pool benchmark")
    args = parser.parse_args()

    print("=" * 70)
    print("VPNProxy Performance Benchmark")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as cert_dir:
        print("\n[1/5] Generating certificates...")
        generate_cert(cert_dir, "ecdsa")
        ecdsa_times = await bench_tls_handshake(cert_dir, "ecdsa", args.iterations)

        generate_cert(cert_dir, "rsa")
        rsa_times = await bench_tls_handshake(cert_dir, "rsa", args.iterations)

        print(f"\n--- TLS Handshake Time ({args.iterations} iterations) ---")
        print(f"  ECDSA P-256:  {fmt_stats(ecdsa_times)}")
        print(f"  RSA-4096:     {fmt_stats(rsa_times)}")
        if ecdsa_times and rsa_times:
            speedup = statistics.mean(rsa_times) / statistics.mean(ecdsa_times)
            print(f"  ECDSA speedup: {speedup:.2f}x faster")

    print("\n[2/5] TCP_NODELAY small-packet RTT...")
    nodelay_results = await bench_tcp_nodelay(args.iterations)
    print(f"\n--- TCP_NODELAY RTT (10 ping-pongs, {args.iterations} iterations) ---")
    print(f"  NODELAY ON:   {fmt_stats(nodelay_results['nodelay_on'])}")
    print(f"  NODELAY OFF:  {fmt_stats(nodelay_results['nodelay_off'])}")
    if nodelay_results["nodelay_on"] and nodelay_results["nodelay_off"]:
        ratio = statistics.mean(nodelay_results["nodelay_off"]) / max(0.001, statistics.mean(nodelay_results["nodelay_on"]))
        print(f"  NODELAY improvement: {ratio:.2f}x")

    print(f"\n[3/5] Socket buffer throughput ({args.size_mb}MB)...")
    throughput_results = await bench_throughput(args.size_mb)
    print(f"\n--- Throughput ({args.size_mb}MB transfer) ---")
    print(f"  Default buffers:  {throughput_results['default_buf']}")
    print(f"  Large buffers:    {throughput_results['large_buf']}")
    default_mbps = throughput_results["default_buf"]["throughput_mbps"]
    large_mbps = throughput_results["large_buf"]["throughput_mbps"]
    if default_mbps > 0:
        print(f"  Large buffer speedup: {large_mbps / default_mbps:.2f}x")

    with tempfile.TemporaryDirectory() as cert_dir:
        print(f"\n[4/5] Full proxy tunnel setup ({args.iterations} iterations)...")
        generate_cert(cert_dir, "ecdsa")
        proxy_results = await bench_full_proxy(cert_dir, args.iterations)
        print(f"\n--- Proxy Tunnel Setup ---")
        print(f"  Tunnel setup: {fmt_stats(proxy_results['tunnel_setup_ms'])}")

        if not args.skip_pool:
            print(f"\n[5/5] Proxy tunnel setup with connection pool ({args.iterations} iterations)...")
            pool_results = await bench_proxy_with_pool(cert_dir, args.iterations)
            print(f"\n--- Tunnel Setup with Pool ---")
            print(f"  Pool hit setup: {fmt_stats(pool_results['pool_setup_ms'])}")
            if proxy_results["tunnel_setup_ms"] and pool_results["pool_setup_ms"]:
                no_pool = statistics.mean(proxy_results["tunnel_setup_ms"])
                with_pool = statistics.mean(pool_results["pool_setup_ms"])
                if with_pool > 0:
                    print(f"  Pool speedup: {no_pool / with_pool:.2f}x")

    print("\n" + "=" * 70)
    print("Benchmark complete.")


if __name__ == "__main__":
    asyncio.run(main())