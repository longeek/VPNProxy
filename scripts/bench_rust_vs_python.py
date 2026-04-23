#!/usr/bin/env python3
"""Compare Python vs Rust VPNProxy server performance.

Starts both servers, then measures:
1. Tunnel setup latency
2. TCP relay throughput
3. Concurrent connection handling
"""

import asyncio
import json
import os
import ssl
import statistics
import subprocess
import sys
import time
import signal

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

TOKEN = "bench-token-" + os.urandom(4).hex()
CERT_DIR = os.path.join(ROOT_DIR, "certs")
CERT_PATH = os.path.join(CERT_DIR, "server.crt")
KEY_PATH = os.path.join(CERT_DIR, "server.key")
RUST_SERVER = os.path.join(ROOT_DIR, "vpn-proxy-rust", "target", "release", "vpn-proxy-server.exe")

async def run_echo_server(port: int) -> asyncio.Server:
    async def handler(reader, writer):
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

    return await asyncio.start_server(handler, "127.0.0.1", port)


async def bench_tunnel_setup(server_port: int, iterations: int = 20) -> list:
    sys.path.insert(0, ROOT_DIR)
    import client as cli

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=server_port,
        token=TOKEN,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
    )

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            reader, writer = await cli.open_tunnel("127.0.0.1", 18080, args, "bench")
            writer.close()
            await writer.wait_closed()
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        except Exception as e:
            print(f"  tunnel setup failed: {e}")
    return times


async def bench_throughput(server_port: int, size_mb: int = 4) -> dict:
    sys.path.insert(0, ROOT_DIR)
    import client as cli

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    args = argparse.Namespace(
        server="127.0.0.1",
        server_port=server_port,
        token=TOKEN,
        ca_cert=None,
        insecure=True,
        sni=None,
        connect_retries=0,
        retry_delay=0.01,
    )

    reader, writer = await cli.open_tunnel("127.0.0.1", 18080, args, "bench-throughput")

    data = b"x" * (64 * 1024)
    total_bytes = size_mb * 1024 * 1024
    sent = 0

    t0 = time.perf_counter()
    while sent < total_bytes:
        chunk = data if (sent + len(data)) <= total_bytes else data[:total_bytes - sent]
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

    writer.close()
    await writer.wait_closed()

    return {
        "throughput_mbps": round(throughput_mb, 2),
        "elapsed_s": round(elapsed, 3),
    }


import argparse


async def main():
    import argparse as ap
    parser = ap.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--size-mb", type=int, default=4)
    parser.add_argument("--skip-rust", action="store_true")
    args = parser.parse_args()

    import subprocess
    import sys

    # Start echo target server
    echo_server = await run_echo_server(18080)
    echo_port = echo_server.sockets[0].getsockname()[1]
    print(f"Echo server on port {echo_port}")

    results = {}

    # === Python server benchmark ===
    print("\n" + "=" * 70)
    print("Python Server Benchmark")
    print("=" * 70)

    python_proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT_DIR, "server.py"),
         "--port", "18443", "--token", TOKEN,
         "--cert", CERT_PATH, "--key", KEY_PATH,
         "--log-level", "WARNING"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    await asyncio.sleep(1)

    try:
        print(f"\n[1/2] Tunnel setup latency ({args.iterations} iterations)...")
        py_setup = await bench_tunnel_setup(18443, args.iterations)
        if py_setup:
            print(f"  Mean:   {statistics.mean(py_setup):.2f}ms")
            print(f"  Median: {statistics.median(py_setup):.2f}ms")
            print(f"  P95:    {sorted(py_setup)[int(len(py_setup)*0.95)]:.2f}ms")
            print(f"  Min:    {min(py_setup):.2f}ms")
            results["py_setup"] = py_setup

        print(f"\n[2/2] Throughput ({args.size_mb}MB transfer)...")
        py_throughput = await bench_throughput(18443, args.size_mb)
        print(f"  Throughput: {py_throughput['throughput_mbps']:.2f} MB/s")
        print(f"  Elapsed: {py_throughput['elapsed_s']:.3f}s")
        results["py_throughput"] = py_throughput
    finally:
        python_proc.terminate()
        python_proc.wait()

    # === Rust server benchmark ===
    if not args.skip_rust and os.path.exists(RUST_SERVER):
        print("\n" + "=" * 70)
        print("Rust Server Benchmark")
        print("=" * 70)

        rust_proc = subprocess.Popen(
            [RUST_SERVER,
             "--port", "18444", "--token", TOKEN,
             "--cert", CERT_PATH, "--key", KEY_PATH,
             "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(1)

        try:
            print(f"\n[1/2] Tunnel setup latency ({args.iterations} iterations)...")
            rs_setup = await bench_tunnel_setup(18444, args.iterations)
            if rs_setup:
                print(f"  Mean:   {statistics.mean(rs_setup):.2f}ms")
                print(f"  Median: {statistics.median(rs_setup):.2f}ms")
                print(f"  P95:    {sorted(rs_setup)[int(len(rs_setup)*0.95)]:.2f}ms")
                print(f"  Min:    {min(rs_setup):.2f}ms")
                results["rs_setup"] = rs_setup

            print(f"\n[2/2] Throughput ({args.size_mb}MB transfer)...")
            rs_throughput = await bench_throughput(18444, args.size_mb)
            print(f"  Throughput: {rs_throughput['throughput_mbps']:.2f} MB/s")
            print(f"  Elapsed: {rs_throughput['elapsed_s']:.3f}s")
            results["rs_throughput"] = rs_throughput
        finally:
            rust_proc.terminate()
            rust_proc.wait()
    elif not args.skip_rust:
        print(f"\nRust server not found at {RUST_SERVER}, skipping Rust benchmark")

    # === Comparison ===
    if "py_setup" in results and "rs_setup" in results:
        print("\n" + "=" * 70)
        print("Comparison: Tunnel Setup Latency")
        print("=" * 70)
        py_mean = statistics.mean(results["py_setup"])
        rs_mean = statistics.mean(results["rs_setup"])
        speedup = py_mean / rs_mean if rs_mean > 0 else float('inf')
        print(f"  Python:  {py_mean:.2f}ms (mean)")
        print(f"  Rust:    {rs_mean:.2f}ms (mean)")
        print(f"  Speedup: {speedup:.2f}x")

    if "py_throughput" in results and "rs_throughput" in results:
        print("\n" + "=" * 70)
        print("Comparison: Throughput")
        print("=" * 70)
        py_tp = results["py_throughput"]["throughput_mbps"]
        rs_tp = results["rs_throughput"]["throughput_mbps"]
        speedup = rs_tp / py_tp if py_tp > 0 else float('inf')
        print(f"  Python:  {py_tp:.2f} MB/s")
        print(f"  Rust:    {rs_tp:.2f} MB/s")
        print(f"  Speedup: {speedup:.2f}x")

    echo_server.close()
    await echo_server.wait_closed()

    print("\n" + "=" * 70)
    print("Benchmark complete.")


if __name__ == "__main__":
    asyncio.run(main())